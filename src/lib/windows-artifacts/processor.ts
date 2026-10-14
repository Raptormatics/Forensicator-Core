/**
 * Windows Artifact Analysis — per-file processing pipeline.
 *
 * Unlike RAM/PCAP Analysis's one-processor-per-upload, this domain
 * processes one WindowsArtifactFile at a time (see the job dispatcher in
 * src/lib/jobs/winartifacts-worker.ts) — a collection can hold several
 * files of different roles, each succeeding or failing independently.
 *
 * 1. Set file status "processing"
 * 2. Wipe prior partial rows for this file in a $transaction (BullMQ retry idempotency)
 * 3. Run the role-appropriate parser (registry-parse.py for hive roles,
 *    prefetch-parse.py for "prefetch"), map rows
 * 4. Batch-insert the role-appropriate rows
 * 5. Upsert global IocRecord for Amcache SHA1 hashes, trigger autoEnrichNewIocs()
 *    (registry roles only — Prefetch has no hash to upsert)
 * 6. Load enabled WindowsArtifactRule (org-scoped OR global) -> rule engine -> WindowsArtifactFinding rows
 * 7. notifyCriticalFindings() best-effort
 * 8. Update file status "ready" + findingCount; recompute parent upload's findingCount
 */
import path from "path";
import { prisma } from "@/lib/db/prisma";
import { getWinArtifactsPythonPath, getPrefetchPythonPath } from "@/lib/settings/system";
import {
  runRegistryParse, mapShimcacheEntries, mapAmcacheEntries, mapBamEntries, mapShellbagEntries,
  type RegistryRole,
} from "./registry-engine";
import { runPrefetchParse, type PrefetchEntryRow } from "./prefetch-engine";
import { runLnkParse, type LnkEntryRow, type LnkRole } from "./lnk-engine";
import { runJumpListParse, type JumpListEntryRow } from "./jumplist-engine";
import { buildSubjects, runRules, type StoredWinArtifactRule } from "./rule-engine";
import { isEnriched, type IocLookupMap } from "@/lib/rule-engine/ioc-lookup";
import { autoEnrichNewIocs, type NewIocRecord } from "@/lib/intelligence/auto-enrich";
import { notifyCriticalFindings } from "@/lib/notifications/critical-finding-alert";

const REGISTRY_ROLES: RegistryRole[] = ["system_hive", "software_hive", "security_hive", "ntuser_hive", "amcache_hive", "usrclass_hive"];
const LNK_ROLES: LnkRole[] = ["lnk", "jumplist_custom"];

export async function processWindowsArtifactFile(fileId: string, filePath: string): Promise<void> {
  const file = await prisma.windowsArtifactFile.findUnique({ where: { id: fileId }, include: { upload: true } });
  if (!file) throw new Error(`WindowsArtifactFile ${fileId} not found`);

  await prisma.windowsArtifactFile.update({ where: { id: fileId }, data: { status: "processing" } });

  try {
    // 2. Idempotency for BullMQ retries — this job fully re-derives
    // everything from the same file, so wipe any partial rows before redoing the work.
    await prisma.$transaction([
      prisma.shimcacheEntry.deleteMany({ where: { fileId } }),
      prisma.amcacheEntry.deleteMany({ where: { fileId } }),
      prisma.userAssistEntry.deleteMany({ where: { fileId } }),
      prisma.bamEntry.deleteMany({ where: { fileId } }),
      prisma.autorunEntry.deleteMany({ where: { fileId } }),
      prisma.prefetchEntry.deleteMany({ where: { fileId } }),
      prisma.lnkEntry.deleteMany({ where: { fileId } }),
      prisma.jumpListEntry.deleteMany({ where: { fileId } }),
      prisma.shellbagEntry.deleteMany({ where: { fileId } }),
      prisma.windowsArtifactFinding.deleteMany({ where: { fileId } }),
    ]);

    let findingTotal = 0;
    let shimcacheRows: ReturnType<typeof mapShimcacheEntries> = [];
    let amcacheRows: ReturnType<typeof mapAmcacheEntries> = [];
    let bamRows: ReturnType<typeof mapBamEntries> = [];
    let userAssistRows: import("./registry-engine").UserAssistRow[] = [];
    let autorunRows: import("./registry-engine").AutorunRow[] = [];
    let shellbagRows: ReturnType<typeof mapShellbagEntries> = [];
    let prefetchRows: PrefetchEntryRow[] = [];
    let lnkRows: LnkEntryRow[] = [];
    let jumpListRows: JumpListEntryRow[] = [];
    const iocLookupMap: IocLookupMap = new Map();

    if (REGISTRY_ROLES.includes(file.role as RegistryRole)) {
      // 3. Run the registry parser
      const pythonPath = await getWinArtifactsPythonPath();
      const result = await runRegistryParse(pythonPath, filePath, file.role as RegistryRole);

      if (result.status === "not_installed") {
        throw new Error("regipy is not installed in the Windows Artifacts venv — see Settings > Windows Artifact Storage Directory.");
      }
      if (result.status === "timeout") {
        throw new Error("Registry parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }

      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] registry-parse.py reported: ${err}`);
      }

      // 4. Map + batch-insert by role
      shimcacheRows = file.role === "system_hive" ? mapShimcacheEntries(result.pluginEntries) : [];
      amcacheRows = file.role === "amcache_hive" ? mapAmcacheEntries(result.pluginEntries) : [];
      bamRows = file.role === "system_hive" ? mapBamEntries(result.pluginEntries) : [];
      shellbagRows = (file.role === "usrclass_hive" || file.role === "ntuser_hive") ? mapShellbagEntries(result.pluginEntries) : [];
      userAssistRows = result.userAssist;
      autorunRows = result.autoruns;

      if (shimcacheRows.length > 0) {
        await prisma.shimcacheEntry.createMany({
          data: shimcacheRows.map((r) => ({
            fileId, path: r.path,
            lastModified: r.lastModified ? new Date(r.lastModified) : undefined,
            executionFlag: r.executionFlag ?? undefined,
            order: r.order,
          })),
        });
      }
      if (amcacheRows.length > 0) {
        await prisma.amcacheEntry.createMany({
          data: amcacheRows.map((r) => ({
            fileId, path: r.path, sha1: r.sha1 ?? undefined,
            fileSizeBytes: r.fileSizeBytes ?? undefined,
            firstSeen: r.firstSeen ? new Date(r.firstSeen) : undefined,
            publisher: r.publisher ?? undefined,
          })),
        });
      }
      if (userAssistRows.length > 0) {
        await prisma.userAssistEntry.createMany({
          data: userAssistRows.map((r) => ({
            fileId, programPath: r.programPath,
            runCount: r.runCount ?? undefined,
            lastExecuted: r.lastExecuted ? new Date(r.lastExecuted) : undefined,
            focusCount: r.focusCount ?? undefined,
            focusTimeMs: r.focusTimeMs ?? undefined,
          })),
        });
      }
      if (bamRows.length > 0) {
        await prisma.bamEntry.createMany({
          data: bamRows.map((r) => ({
            fileId, sid: r.sid, path: r.path,
            lastExecuted: r.lastExecuted ? new Date(r.lastExecuted) : undefined,
          })),
        });
      }
      if (autorunRows.length > 0) {
        await prisma.autorunEntry.createMany({
          data: autorunRows.map((r) => ({
            fileId, hiveSource: r.hiveSource, keyPath: r.keyPath,
            valueName: r.valueName ?? undefined, valueData: r.valueData, category: r.category,
          })),
        });
      }
      if (shellbagRows.length > 0) {
        await prisma.shellbagEntry.createMany({
          data: shellbagRows.map((r) => ({
            fileId, path: r.path, nodeName: r.nodeName, nodeSlot: r.nodeSlot, depth: r.depth,
            itemType: r.itemType ?? undefined,
            creationTime: r.creationTime ? new Date(r.creationTime) : undefined,
            accessTime: r.accessTime ? new Date(r.accessTime) : undefined,
            lastModified: r.lastModified ? new Date(r.lastModified) : undefined,
          })),
        });
      }

      // 5. Amcache SHA1 -> global IocRecord, so the rule engine's ioc_known
      // condition and the broader threat-intel DB both see these hashes.
      const now = new Date();
      const newIocRecords: NewIocRecord[] = [];
      const distinctHashes = new Set(amcacheRows.map((r) => r.sha1).filter((h): h is string => !!h));

      for (const hash of distinctHashes) {
        try {
          const existing = await prisma.iocRecord.findUnique({ where: { value: hash } });
          if (existing) {
            iocLookupMap.set(hash, { reputation: existing.reputation, threatType: existing.threatType, malwareFamily: existing.malwareFamily });
          }
          const rec = await prisma.iocRecord.upsert({
            where: { value: hash },
            create: { value: hash, type: "hash", firstSeen: now, lastSeen: now },
            update: { lastSeen: now },
          });
          if (!existing) newIocRecords.push({ id: rec.id, value: rec.value, type: "hash" });
        } catch (iocErr) {
          console.warn("[windows-artifacts] IocRecord row skipped:", hash, iocErr instanceof Error ? iocErr.message : iocErr);
        }
      }
      if (newIocRecords.length > 0) {
        await autoEnrichNewIocs(newIocRecords, file.upload.organizationId ?? undefined).catch((err) =>
          console.warn("[windows-artifacts] Auto-enrichment skipped:", err instanceof Error ? err.message : err)
        );
      }
    } else if (file.role === "prefetch") {
      // 3. Run the Prefetch parser (system python3 + pyscca, not the
      // winartifacts venv — see getPrefetchPythonPath()'s own doc comment).
      const pythonPath = await getPrefetchPythonPath();
      const result = await runPrefetchParse(pythonPath, filePath);

      if (result.status === "not_installed") {
        throw new Error("pyscca (python3-libscca) is not installed — see deploy/provision.sh.");
      }
      if (result.status === "timeout") {
        throw new Error("Prefetch parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] prefetch-parse.py reported: ${err}`);
      }

      // 4. One PrefetchEntry row per file (a .pf file is one executable).
      if (result.entry) {
        prefetchRows = [result.entry];
        await prisma.prefetchEntry.create({
          data: {
            fileId,
            executableName: result.entry.executableName,
            runCount: result.entry.runCount ?? undefined,
            lastRunTimes: result.entry.lastRunTimes.map((t) => new Date(t)).filter((d) => !isNaN(d.getTime())),
            firstRunTime: result.entry.lastRunTimes.length > 0
              ? new Date(Math.min(...result.entry.lastRunTimes.map((t) => new Date(t).getTime()).filter((n) => !isNaN(n))))
              : undefined,
            volumeSerials: result.entry.volumeSerials,
            referencedFiles: result.entry.referencedFiles,
          },
        });
      }
      // No IOC upsert step — Prefetch carries no hash to look up.
    } else if (LNK_ROLES.includes(file.role as LnkRole)) {
      // 3. Run the LNK parser — same winartifacts venv as regipy (pure
      // Python, no C-library linking concern unlike pyscca). Handles both
      // a standalone .lnk and the embedded LNKs inside a
      // .customDestinations-ms container (same parser, selected by role).
      const pythonPath = await getWinArtifactsPythonPath();
      const result = await runLnkParse(pythonPath, filePath, file.role as LnkRole);

      if (result.status === "not_installed") {
        throw new Error("LnkParse3 is not installed in the Windows Artifacts venv.");
      }
      if (result.status === "timeout") {
        throw new Error("LNK parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] lnk-parse.py reported: ${err}`);
      }

      if (file.role === "lnk") {
        // 4. One LnkEntry row for this standalone shortcut.
        lnkRows = result.entries;
        if (lnkRows.length > 0) {
          await prisma.lnkEntry.createMany({
            data: lnkRows.map((r) => ({
              fileId,
              targetPath: r.targetPath ?? undefined,
              arguments: r.arguments ?? undefined,
              workingDirectory: r.workingDirectory ?? undefined,
              iconLocation: r.iconLocation ?? undefined,
              creationTime: r.creationTime ? new Date(r.creationTime) : undefined,
              accessTime: r.accessTime ? new Date(r.accessTime) : undefined,
              modificationTime: r.modificationTime ? new Date(r.modificationTime) : undefined,
              fileSize: r.fileSize ?? undefined,
              driveSerialNumber: r.driveSerialNumber ?? undefined,
              driveType: r.driveType ?? undefined,
              volumeLabel: r.volumeLabel ?? undefined,
              netName: r.netName ?? undefined,
              deviceName: r.deviceName ?? undefined,
              machineId: r.machineId ?? undefined,
            })),
          });
        }
      } else {
        // 4. jumplist_custom — one JumpListEntry row per embedded LNK,
        // alongside jumplist_automatic in the same table (same conceptual
        // artifact — "this app recently opened this file" — just with no
        // DestList-backed rank/machine/pin metadata to carry).
        jumpListRows = result.entries.map((r) => ({
          streamNumber: "", targetPath: r.targetPath, arguments: r.arguments,
          workingDirectory: r.workingDirectory, lastAccessed: r.accessTime,
          accessRank: null, pinned: null, machineName: null,
        }));
        // path.basename() — file.filename may carry a folder-picker's relative
        // path (e.g. "FAVOUR/abc123.customDestinations-ms") now that uploads
        // can preserve per-profile subfolder context; the AppID hash itself
        // is always just the bare filename's stem.
        const appId = path.basename(file.filename).replace(/\.customDestinations-ms$/i, "");
        if (jumpListRows.length > 0) {
          await prisma.jumpListEntry.createMany({
            data: jumpListRows.map((r) => ({
              fileId, source: "custom", appId,
              targetPath: r.targetPath ?? undefined,
              arguments: r.arguments ?? undefined,
              workingDirectory: r.workingDirectory ?? undefined,
              lastAccessed: r.lastAccessed ? new Date(r.lastAccessed) : undefined,
            })),
          });
        }
      }
      // No IOC upsert step — LNK/Jump List carries no hash to look up.
    } else if (file.role === "jumplist_automatic") {
      // 3. Run the Jump List parser (olefile + LnkParse3, same venv).
      const pythonPath = await getWinArtifactsPythonPath();
      const result = await runJumpListParse(pythonPath, filePath);

      if (result.status === "not_installed") {
        throw new Error("olefile/LnkParse3 are not installed in the Windows Artifacts venv.");
      }
      if (result.status === "timeout") {
        throw new Error("Jump List parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] jumplist-parse.py reported: ${err}`);
      }

      // 4. One JumpListEntry row per numbered OLE stream (one per
      // recently-opened file/action the application tracked).
      jumpListRows = result.entries;
      // The uploaded file's own name carries the AppID hash
      // (e.g. "5f7b5f1e01b83767.automaticDestinations-ms") — not resolved
      // to a friendly app name, no attempt at hand-maintaining the public
      // AppID-to-app lookup table.
      const appId = path.basename(file.filename).replace(/\.automaticDestinations-ms$/i, "");
      if (jumpListRows.length > 0) {
        await prisma.jumpListEntry.createMany({
          data: jumpListRows.map((r) => ({
            fileId, source: "automatic", appId,
            targetPath: r.targetPath ?? undefined,
            arguments: r.arguments ?? undefined,
            workingDirectory: r.workingDirectory ?? undefined,
            lastAccessed: r.lastAccessed ? new Date(r.lastAccessed) : undefined,
            accessRank: r.accessRank ?? undefined,
            pinned: r.pinned ?? undefined,
            machineName: r.machineName ?? undefined,
            streamNumber: r.streamNumber,
          })),
        });
      }
      // No IOC upsert step — Jump Lists carry no hash to look up.
    } else {
      throw new Error(`Unsupported artifact role (not yet implemented): ${file.role}`);
    }

    // 6. Analyst-defined rules (org-scoped OR global)
    const rules = await prisma.windowsArtifactRule.findMany({
      where: {
        enabled: true,
        OR: [
          ...(file.upload.organizationId ? [{ organizationId: file.upload.organizationId }] : []),
          { organizationId: null },
        ],
      },
    });

    const criticalCandidates: { title: string; severity: string; sourceLabel: string; detailPath: string }[] = [];
    const detailPath = `/windows-artifacts/${file.uploadId}`;

    if (rules.length > 0) {
      const subjects = buildSubjects({
        shimcache: shimcacheRows, amcache: amcacheRows, userAssist: userAssistRows, bam: bamRows, autoruns: autorunRows,
        prefetch: prefetchRows, lnk: lnkRows, jumplist: jumpListRows, shellbag: shellbagRows,
      });
      const matches = runRules(rules as unknown as StoredWinArtifactRule[], subjects, iocLookupMap);

      const byRule = new Map<string, typeof matches>();
      for (const m of matches) {
        const arr = byRule.get(m.ruleId) ?? [];
        arr.push(m);
        byRule.set(m.ruleId, arr);
      }

      for (const [ruleId, hits] of byRule.entries()) {
        const rule = rules.find((r) => r.id === ruleId);
        if (!rule) continue;
        const sample = hits[0];

        await prisma.windowsArtifactFinding.create({
          data: {
            fileId, ruleId,
            title: rule.name, description: rule.description ?? undefined, severity: rule.severity,
            matchCount: hits.length,
            matchedField: sample.matchedField, matchedValue: sample.matchedValue,
          },
        });
        findingTotal++;
        criticalCandidates.push({ title: rule.name, severity: rule.severity, sourceLabel: "Windows Artifacts", detailPath });

        await prisma.windowsArtifactRule.update({ where: { id: ruleId }, data: { hitCount: { increment: hits.length } } });
      }
    }

    await notifyCriticalFindings(criticalCandidates).catch((err) =>
      console.warn("[windows-artifacts] Critical finding alert failed:", err instanceof Error ? err.message : err)
    );

    // 8. Final status + counts
    await prisma.windowsArtifactFile.update({
      where: { id: fileId },
      data: { status: "ready", findingCount: findingTotal, errorMessage: null, parsedAt: new Date() },
    });

    const totalFindings = await prisma.windowsArtifactFinding.count({ where: { file: { uploadId: file.uploadId } } });
    await prisma.windowsArtifactUpload.update({ where: { id: file.uploadId }, data: { findingCount: totalFindings } });
  } catch (err) {
    await prisma.windowsArtifactFile.update({
      where: { id: fileId },
      data: { status: "failed", errorMessage: err instanceof Error ? err.message : String(err) },
    });
    throw err;
  }
}
