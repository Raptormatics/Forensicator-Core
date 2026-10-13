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
 * 3. Run registry-parse.py via runRegistryParse(), map rows by role
 * 4. Batch-insert Shimcache/Amcache/UserAssist/BAM/Autorun rows
 * 5. Upsert global IocRecord for Amcache SHA1 hashes, trigger autoEnrichNewIocs()
 * 6. Load enabled WindowsArtifactRule (org-scoped OR global) -> rule engine -> WindowsArtifactFinding rows
 * 7. notifyCriticalFindings() best-effort
 * 8. Update file status "ready" + findingCount; recompute parent upload's findingCount
 */
import { prisma } from "@/lib/db/prisma";
import { getWinArtifactsPythonPath } from "@/lib/settings/system";
import {
  runRegistryParse, mapShimcacheEntries, mapAmcacheEntries, mapBamEntries,
  type RegistryRole,
} from "./registry-engine";
import { buildSubjects, runRules, type StoredWinArtifactRule } from "./rule-engine";
import { isEnriched, type IocLookupMap } from "@/lib/rule-engine/ioc-lookup";
import { autoEnrichNewIocs, type NewIocRecord } from "@/lib/intelligence/auto-enrich";
import { notifyCriticalFindings } from "@/lib/notifications/critical-finding-alert";

const REGISTRY_ROLES: RegistryRole[] = ["system_hive", "software_hive", "ntuser_hive", "amcache_hive"];

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
      prisma.windowsArtifactFinding.deleteMany({ where: { fileId } }),
    ]);

    if (!REGISTRY_ROLES.includes(file.role as RegistryRole)) {
      // Prefetch/LNK/JumpList roles are routed here in later phases — not
      // yet implemented, so a file uploaded with one of those roles today
      // just fails cleanly rather than silently doing nothing.
      throw new Error(`Unsupported artifact role (not yet implemented): ${file.role}`);
    }

    // 3. Run the registry parser
    const pythonPath = await getWinArtifactsPythonPath();
    const result = await runRegistryParse(pythonPath, filePath, file.role as RegistryRole);

    let findingTotal = 0;

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
    const shimcacheRows = file.role === "system_hive" ? mapShimcacheEntries(result.pluginEntries) : [];
    const amcacheRows = file.role === "amcache_hive" ? mapAmcacheEntries(result.pluginEntries) : [];
    const bamRows = file.role === "system_hive" ? mapBamEntries(result.pluginEntries) : [];
    const userAssistRows = result.userAssist;
    const autorunRows = result.autoruns;

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

    // 5. Amcache SHA1 -> global IocRecord, so the rule engine's ioc_known
    // condition and the broader threat-intel DB both see these hashes.
    const now = new Date();
    const iocLookupMap: IocLookupMap = new Map();
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
      const subjects = buildSubjects({ shimcache: shimcacheRows, amcache: amcacheRows, userAssist: userAssistRows, bam: bamRows, autoruns: autorunRows });
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
