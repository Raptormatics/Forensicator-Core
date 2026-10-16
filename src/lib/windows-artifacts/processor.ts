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
import fs from "fs";
import path from "path";
import { randomUUID } from "crypto";
import { prisma } from "@/lib/db/prisma";
import { getWinArtifactsPythonPath, getPrefetchPythonPath, getWinArtifactsSystemPythonPath, getWinArtifactsDir } from "@/lib/settings/system";
import {
  runRegistryParse, mapShimcacheEntries, mapAmcacheEntries, mapBamEntries, mapShellbagEntries,
  type RegistryRole,
} from "./registry-engine";
import { runPrefetchParse, type PrefetchEntryRow } from "./prefetch-engine";
import { runLnkParse, type LnkEntryRow, type LnkRole } from "./lnk-engine";
import { runJumpListParse, type JumpListEntryRow } from "./jumplist-engine";
import { runMftParse, type MftEntryRow } from "./mft-engine";
import { runUsnJrnlParse, type UsnJrnlEntryRow } from "./usnjrnl-engine";
import { runSrumParse, type SrumEntryRow } from "./srum-engine";
import { runWerReportParse, type WerReportRow } from "./wer-engine";
import { runWerDumpParse, type WerDumpRow } from "./wer-dump-engine";
import { runRecycleBinParse, type RecycleBinRow } from "./recyclebin-engine";
import { runNotificationParse, type NotificationRow } from "./notification-engine";
import { runSearchIndexParse, type SearchIndexRow } from "./search-engine";
import { runBitsParse, type BitsJobRow } from "./bits-engine";
import { runQuarantineEntryParse, runQuarantinePayloadParse, type QuarantineEntryRow, type QuarantinePayloadRow } from "./defender-quarantine-engine";
import { buildSubjects, runRules, type StoredWinArtifactRule } from "./rule-engine";
import { isEnriched, type IocLookupMap } from "@/lib/rule-engine/ioc-lookup";
import { autoEnrichNewIocs, type NewIocRecord } from "@/lib/intelligence/auto-enrich";
import { notifyCriticalFindings } from "@/lib/notifications/critical-finding-alert";

const REGISTRY_ROLES: RegistryRole[] = ["system_hive", "software_hive", "security_hive", "ntuser_hive", "amcache_hive", "usrclass_hive"];
const LNK_ROLES: LnkRole[] = ["lnk", "jumplist_custom"];

// Prisma/Postgres have a practical parameter-count limit per query that
// the existing small-row-count artifact types never had to think about —
// $MFT/$UsnJrnl:$J can run into the hundreds of thousands to millions of
// rows, so their createMany calls are chunked rather than one unbounded array.
const BULK_INSERT_CHUNK_SIZE = 2000;

async function chunkedCreateMany<T>(
  create: (data: T[]) => Promise<unknown>,
  rows: T[],
  chunkSize = BULK_INSERT_CHUNK_SIZE
): Promise<void> {
  for (let i = 0; i < rows.length; i += chunkSize) {
    await create(rows.slice(i, i + chunkSize));
  }
}

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
      prisma.mftEntry.deleteMany({ where: { fileId } }),
      prisma.usnJrnlEntry.deleteMany({ where: { fileId } }),
      prisma.srumEntry.deleteMany({ where: { fileId } }),
      prisma.werReportEntry.deleteMany({ where: { fileId } }),
      prisma.werDumpEntry.deleteMany({ where: { fileId } }),
      prisma.recycleBinEntry.deleteMany({ where: { fileId } }),
      prisma.notificationEntry.deleteMany({ where: { fileId } }),
      prisma.searchIndexEntry.deleteMany({ where: { fileId } }),
      prisma.defenderQuarantineEntry.deleteMany({ where: { fileId } }),
      prisma.defenderQuarantinePayload.deleteMany({ where: { fileId } }),
      prisma.bitsJobEntry.deleteMany({ where: { fileId } }),
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
    let mftRows: MftEntryRow[] = [];
    let usnJrnlRows: UsnJrnlEntryRow[] = [];
    let srumRows: SrumEntryRow[] = [];
    let werReportRows: WerReportRow[] = [];
    let werDumpRows: WerDumpRow[] = [];
    let bitsRows: BitsJobRow[] = [];
    let recycleBinRows: RecycleBinRow[] = [];
    let quarantinePayloadRows: QuarantinePayloadRow[] = [];
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

      // software_hive only — persist the SRUM\Extensions GUID->DllName
      // map at the upload level so a srum_db file's own processing (in
      // this same collection, whenever it runs — order-independent) can
      // cross-check table GUIDs against what's actually registered on
      // this system. Not required for SRUM parsing to work at all (see
      // srum-engine.ts) — just extra context when available.
      if (file.role === "software_hive" && result.srumExtensions.length > 0) {
        const map: Record<string, string> = {};
        for (const ext of result.srumExtensions) {
          if (ext.dllName) map[ext.guid] = ext.dllName;
        }
        if (Object.keys(map).length > 0) {
          await prisma.windowsArtifactUpload.update({
            where: { id: file.uploadId },
            data: { srumExtensionsMap: map },
          });
        }
      }

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
    } else if (file.role === "mft") {
      // 3. Run the $MFT parser (system python3 + pyfsntfs, same
      // C-linked-library tier as Prefetch's pyscca).
      const pythonPath = await getWinArtifactsSystemPythonPath();
      const result = await runMftParse(pythonPath, filePath);

      if (result.status === "not_installed") {
        throw new Error("pyfsntfs (libfsntfs-python) is not installed — see deploy/install-winartifacts-deps.sh.");
      }
      if (result.status === "timeout") {
        throw new Error("$MFT parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] mft-parse.py reported: ${err}`);
      }

      // 4. One MftEntry row per parsed entry — a real $MFT can run into
      // the hundreds of thousands to low millions of rows, so inserted
      // in chunks rather than one unbounded createMany call.
      mftRows = result.entries;
      await chunkedCreateMany(
        (data) => prisma.mftEntry.createMany({ data }),
        mftRows.map((r) => ({
          fileId,
          mftEntryNumber: r.mftEntryNumber,
          sequenceNumber: r.sequenceNumber ?? undefined,
          name: r.name,
          path: r.path ?? undefined,
          parentEntryNumber: r.parentEntryNumber ?? undefined,
          isAllocated: r.isAllocated,
          isDirectory: r.isDirectory,
          creationTime: r.creationTime ? new Date(r.creationTime) : undefined,
          modificationTime: r.modificationTime ? new Date(r.modificationTime) : undefined,
          accessTime: r.accessTime ? new Date(r.accessTime) : undefined,
          entryModificationTime: r.entryModificationTime ? new Date(r.entryModificationTime) : undefined,
          fileSize: r.fileSize != null ? BigInt(r.fileSize) : undefined,
          hasAlternateDataStreams: r.hasAlternateDataStreams,
        }))
      );
      // No IOC upsert step — $MFT carries no hash to look up.
    } else if (file.role === "usnjrnl") {
      // 3. Run the $UsnJrnl:$J parser — pure stdlib struct parsing, same
      // winartifacts venv as regipy/LnkParse3 (no C library involved).
      const pythonPath = await getWinArtifactsPythonPath();
      const result = await runUsnJrnlParse(pythonPath, filePath);

      if (result.status === "not_installed") {
        throw new Error("usnjrnl-parse.py reported itself unavailable.");
      }
      if (result.status === "timeout") {
        throw new Error("$UsnJrnl:$J parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] usnjrnl-parse.py reported: ${err}`);
      }

      // 4. One UsnJrnlEntry row per decoded USN record — same chunked
      // insert reasoning as $MFT above (can also run into the millions).
      usnJrnlRows = result.entries;
      await chunkedCreateMany(
        (data) => prisma.usnJrnlEntry.createMany({ data }),
        usnJrnlRows.map((r) => ({
          fileId,
          usn: BigInt(r.usn),
          fileReferenceNumber: r.fileReferenceNumber,
          parentFileReferenceNumber: r.parentFileReferenceNumber,
          timestamp: r.timestamp ? new Date(r.timestamp) : undefined,
          reason: r.reason,
          fileName: r.fileName ?? undefined,
          fileAttributes: r.fileAttributes ?? undefined,
          sourceInfo: r.sourceInfo ?? undefined,
        }))
      );
      // No IOC upsert step — $UsnJrnl:$J carries no hash to look up.
    } else if (file.role === "srum_db") {
      // 3. Run the SRUM parser (system python3 + pyesedb, same
      // C-linked-library tier as $MFT/Prefetch). Passes along the
      // upload-level SRUM\Extensions registry map, if a software_hive
      // file in this same collection already set one (see the
      // REGISTRY_ROLES branch above) — order-independent, null is fine.
      const pythonPath = await getWinArtifactsSystemPythonPath();
      const extensionsMap = (file.upload.srumExtensionsMap as Record<string, string> | null) ?? null;
      const result = await runSrumParse(pythonPath, filePath, extensionsMap);

      if (result.status === "not_installed") {
        throw new Error("pyesedb (libesedb-python) is not installed — see deploy/install-winartifacts-deps.sh.");
      }
      if (result.status === "timeout") {
        throw new Error("SRUDB.dat parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] srum-parse.py reported: ${err}`);
      }

      // 4. One SrumEntry row per ESE record — modest row counts (hundreds
      // to low thousands), unlike $MFT/$UsnJrnl, so a plain createMany.
      srumRows = result.entries;
      if (srumRows.length > 0) {
        await prisma.srumEntry.createMany({
          data: srumRows.map((r) => ({
            fileId,
            tableName: r.tableName,
            providerLabel: r.providerLabel ?? undefined,
            timestamp: r.timestamp ? new Date(r.timestamp) : undefined,
            appId: r.appId ?? undefined,
            userSid: r.userSid ?? undefined,
            details: r.details as object,
          })),
        });
      }
      // No IOC upsert step — SRUM carries no hash to look up.
    } else if (file.role === "wer_report") {
      // 3. Run the Report.wer parser — pure text parsing, same
      // winartifacts venv as regipy (no library dependency at all).
      const pythonPath = await getWinArtifactsPythonPath();
      const result = await runWerReportParse(pythonPath, filePath);

      if (result.status === "not_installed") {
        throw new Error("wer-parse.py reported itself unavailable.");
      }
      if (result.status === "timeout") {
        throw new Error("Report.wer parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] wer-parse.py reported: ${err}`);
      }

      // 4. One WerReportEntry row for this report.
      if (result.entry) {
        werReportRows = [result.entry];
        await prisma.werReportEntry.create({
          data: {
            fileId,
            sourceFileName: file.filename,
            eventType: result.entry.eventType ?? undefined,
            eventTime: result.entry.eventTime ? new Date(result.entry.eventTime) : undefined,
            reportGuid: result.entry.reportGuid ?? undefined,
            appName: result.entry.appName ?? undefined,
            appVersion: result.entry.appVersion ?? undefined,
            appTimestamp: result.entry.appTimestamp ?? undefined,
            faultModuleName: result.entry.faultModuleName ?? undefined,
            faultModuleVersion: result.entry.faultModuleVersion ?? undefined,
            faultModuleTimestamp: result.entry.faultModuleTimestamp ?? undefined,
            exceptionCode: result.entry.exceptionCode ?? undefined,
            exceptionOffset: result.entry.exceptionOffset ?? undefined,
            sigFields: result.entry.sigFields as object,
            rawFields: result.entry.rawFields as object,
          },
        });
      }
      // No IOC upsert step — Report.wer carries no hash to look up.
    } else if (file.role === "wer_dump") {
      // 3. Run the minidump parser (pure-Python `minidump` package, same
      // winartifacts venv — no C library involved).
      const pythonPath = await getWinArtifactsPythonPath();
      const result = await runWerDumpParse(pythonPath, filePath);

      if (result.status === "not_installed") {
        throw new Error("minidump is not installed in the Windows Artifacts venv.");
      }
      if (result.status === "timeout") {
        throw new Error("Minidump parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] wer-dump-parse.py reported: ${err}`);
      }

      // 4. One WerDumpEntry row for this dump.
      if (result.entry) {
        werDumpRows = [result.entry];
        await prisma.werDumpEntry.create({
          data: {
            fileId,
            sourceFileName: file.filename,
            exceptionCode: result.entry.exceptionCode ?? undefined,
            exceptionAddress: result.entry.exceptionAddress ?? undefined,
            faultingThreadId: result.entry.faultingThreadId ?? undefined,
            processId: result.entry.processId ?? undefined,
            processCreateTime: result.entry.processCreateTime ? new Date(result.entry.processCreateTime) : undefined,
            osVersion: result.entry.osVersion ?? undefined,
            cpuArchitecture: result.entry.cpuArchitecture ?? undefined,
            moduleList: result.entry.moduleList as object,
            miscInfo: result.entry.miscInfo as object,
          },
        });
      }
      // No IOC upsert step — a minidump carries no hash to look up.
    } else if (file.role === "recycle_bin") {
      // 3. Run the $I metadata parser — pure stdlib struct, same
      // winartifacts venv as $UsnJrnl:$J (no library needed).
      const pythonPath = await getWinArtifactsPythonPath();
      const result = await runRecycleBinParse(pythonPath, filePath);

      if (result.status === "not_installed") {
        throw new Error("recyclebin-parse.py reported itself unavailable.");
      }
      if (result.status === "timeout") {
        throw new Error("Recycle Bin parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] recyclebin-parse.py reported: ${err}`);
      }

      // 4. One RecycleBinEntry row for this $I file. `sid` comes from the
      // collector's own folder structure ($Recycle.Bin\<SID>\$I...),
      // preserved in profileName at upload time the same way LNK/Jump
      // Lists preserve a per-profile relative path.
      recycleBinRows = result.entries;
      if (recycleBinRows.length > 0) {
        await prisma.recycleBinEntry.createMany({
          data: recycleBinRows.map((r) => ({
            fileId,
            sid: file.profileName ?? "unknown",
            sourceFileName: file.filename,
            formatVersion: r.formatVersion,
            originalPath: r.originalPath,
            deletedTime: r.deletedTime ? new Date(r.deletedTime) : undefined,
            fileSizeBytes: r.fileSizeBytes != null ? BigInt(r.fileSizeBytes) : undefined,
          })),
        });
      }
      // No IOC upsert step — Recycle Bin metadata carries no hash to look up.
    } else if (file.role === "notification_db") {
      // 3. Run the notification database parser — stdlib sqlite3 only,
      // same winartifacts venv (no new dependency at all).
      const pythonPath = await getWinArtifactsPythonPath();
      const result = await runNotificationParse(pythonPath, filePath);

      if (result.status === "not_installed") {
        throw new Error("notification-parse.py reported itself unavailable.");
      }
      if (result.status === "timeout") {
        throw new Error("Notification database parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] notification-parse.py reported: ${err}`);
      }

      // 4. One NotificationEntry row per notification record.
      if (result.entries.length > 0) {
        await prisma.notificationEntry.createMany({
          data: result.entries.map((r) => ({
            fileId,
            profileName: file.profileName ?? undefined,
            arrivalTime: r.arrivalTime ? new Date(r.arrivalTime) : undefined,
            expiryTime: r.expiryTime ? new Date(r.expiryTime) : undefined,
            notifType: r.notifType ?? undefined,
            tag: r.tag ?? undefined,
            groupName: r.groupName ?? undefined,
            handlerId: r.handlerId ?? undefined,
            handlerLabel: r.handlerLabel ?? undefined,
            payload: r.payload ?? undefined,
            details: r.details as object,
          })),
        });
      }
      // No IOC upsert step — deliberately not fed into the rule engine
      // either (see windows-artifacts plan's Decisions) — no reliable
      // structured path/hash field across realistic real-world schemas.
    } else if (file.role === "search_edb") {
      // 3. Run the Windows Search parser (system python3 + pyesedb, same
      // C-linked-library tier as SRUM/$MFT).
      const pythonPath = await getWinArtifactsSystemPythonPath();
      const result = await runSearchIndexParse(pythonPath, filePath);

      if (result.status === "not_installed") {
        throw new Error("pyesedb (libesedb-python) is not installed — see deploy/install-winartifacts-deps.sh.");
      }
      if (result.status === "timeout") {
        throw new Error("Windows Search database parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] search-parse.py reported: ${err}`);
      }

      // 4. One SearchIndexEntry row per ESE record — can be large (every
      // indexed file on the host), same chunked-insert reasoning as
      // $MFT/$UsnJrnl.
      const searchRows: SearchIndexRow[] = result.entries;
      await chunkedCreateMany(
        (data) => prisma.searchIndexEntry.createMany({ data }),
        searchRows.map((r) => ({
          fileId,
          tableName: r.tableName,
          recordIndex: r.recordIndex,
          details: r.details as object,
        }))
      );
      // No IOC upsert step — deliberately not fed into the rule engine
      // either (see windows-artifacts plan's Decisions) — real-world
      // column names are frequently per-install-specific/obfuscated.
    } else if (file.role === "quarantine_entry") {
      // 3. RC4-decrypt and parse the QuarantineEntry metadata file — pure
      // Python (hand-rolled RC4 + TLV reader), same winartifacts venv.
      const pythonPath = await getWinArtifactsPythonPath();
      const result = await runQuarantineEntryParse(pythonPath, filePath);

      if (result.status === "not_installed") {
        throw new Error("defender-quarantine-parse.py reported itself unavailable.");
      }
      if (result.status === "timeout") {
        throw new Error("Defender quarantine entry parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] defender-quarantine-parse.py reported: ${err}`);
      }

      // 4. One DefenderQuarantineEntry row for this file — resources
      // stored as JSON (see Prisma schema comment: no verified filename/
      // ID convention links a specific resource to a specific
      // ResourceData file, so this isn't modeled as a relational FK).
      if (result.entry) {
        const entry: QuarantineEntryRow = result.entry;
        await prisma.defenderQuarantineEntry.create({
          data: {
            fileId,
            sourceFileName: file.filename,
            entryIdHex: entry.entryIdHex ?? undefined,
            scanIdHex: entry.scanIdHex ?? undefined,
            threatId: entry.threatId ?? undefined,
            detectionName: entry.detectionName ?? undefined,
            timestamp: entry.timestamp ? new Date(entry.timestamp) : undefined,
            resources: entry.resources as unknown as object,
            rawFields: entry.rawFields as object,
          },
        });
      }
      // No IOC upsert step here — the hash-bearing artifact is the
      // paired ResourceData file (quarantine_resource role, below).
    } else if (file.role === "quarantine_resource") {
      // 3. RC4-decrypt the ResourceData payload file, writing the
      // decrypted bytes to disk (user-confirmed: Core stores and offers
      // the decrypted file for download, not just hash+metadata — see
      // windows-artifacts plan's Decisions). Deterministic filename
      // (fileId-keyed, not random) so reprocessing overwrites cleanly
      // instead of orphaning a stale copy.
      const pythonPath = await getWinArtifactsPythonPath();
      const winArtifactsDir = await getWinArtifactsDir();
      const payloadDir = path.join(winArtifactsDir, "quarantine-payloads");
      fs.mkdirSync(payloadDir, { recursive: true });
      const decryptedOutputPath = path.join(payloadDir, `${fileId}.bin`);

      const result = await runQuarantinePayloadParse(pythonPath, filePath, decryptedOutputPath);

      if (result.status === "not_installed") {
        throw new Error("defender-quarantine-parse.py reported itself unavailable.");
      }
      if (result.status === "timeout") {
        throw new Error("Defender quarantine payload parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] defender-quarantine-parse.py reported: ${err}`);
      }

      // 4. One DefenderQuarantinePayload row for this file.
      if (result.entry) {
        quarantinePayloadRows = [result.entry];
        await prisma.defenderQuarantinePayload.create({
          data: {
            fileId,
            sourceFileName: file.filename,
            magicValid: result.entry.magicValid,
            sha256: result.entry.sha256 ?? undefined,
            decryptedSizeBytes: result.entry.decryptedSizeBytes != null ? BigInt(result.entry.decryptedSizeBytes) : undefined,
            decryptedStoragePath: result.entry.magicValid ? decryptedOutputPath : undefined,
            fileTypeSniff: result.entry.fileTypeSniff ?? undefined,
          },
        });
      }

      // 5. Decrypted payload SHA256 -> global IocRecord — identical
      // pattern to the existing Amcache-SHA1 block above, just a
      // different subject kind feeding it (see rule-engine.ts's
      // iocCandidates(), which already checks both subject.sha1 and
      // subject.sha256).
      const now = new Date();
      const newIocRecords: NewIocRecord[] = [];
      const distinctHashes = new Set(quarantinePayloadRows.map((r) => r.sha256).filter((h): h is string => !!h));

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
    } else if (file.role === "bits_queue") {
      // 3. Run the BITS queue parser (bits_parser package, same
      // winartifacts venv — pure Python, no C library). Legacy
      // qmgr0.dat/qmgr1.dat format only — see windows-artifacts plan's
      // Decisions for why the newer ESE-based qmgr.db is out of scope.
      const pythonPath = await getWinArtifactsPythonPath();
      const result = await runBitsParse(pythonPath, filePath);

      if (result.status === "not_installed") {
        throw new Error("bits_parser is not installed in the Windows Artifacts venv.");
      }
      if (result.status === "timeout") {
        throw new Error("BITS queue parsing timed out.");
      }
      if (result.status === "error") {
        throw new Error(result.message);
      }
      for (const err of result.scriptErrors) {
        console.warn(`[windows-artifacts] bits-parse.py reported: ${err}`);
      }

      // 4. One BitsJobEntry row per (job, file-transfer) pair.
      bitsRows = result.entries;
      if (bitsRows.length > 0) {
        await prisma.bitsJobEntry.createMany({
          data: bitsRows.map((r) => ({
            fileId,
            jobId: r.jobId ?? undefined,
            name: r.name ?? undefined,
            desc: r.desc ?? undefined,
            cmd: r.cmd ?? undefined,
            sid: r.sid ?? undefined,
            jobType: r.jobType ?? undefined,
            priority: r.priority ?? undefined,
            state: r.state ?? undefined,
            ctime: r.ctime ? new Date(r.ctime) : undefined,
            mtime: r.mtime ? new Date(r.mtime) : undefined,
            destFn: r.destFn ?? undefined,
            srcFn: r.srcFn ?? undefined,
            tmpFn: r.tmpFn ?? undefined,
            downloadSizeBytes: r.downloadSizeBytes != null ? BigInt(r.downloadSizeBytes) : undefined,
            transferSizeBytes: r.transferSizeBytes != null ? BigInt(r.transferSizeBytes) : undefined,
            isCarved: r.isCarved,
          })),
        });
      }
      // No IOC upsert step — BITS job records carry no hash to look up.
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
        mft: mftRows, usnjrnl: usnJrnlRows, srum: srumRows,
        wer: werReportRows, werDump: werDumpRows, recyclebin: recycleBinRows, bits: bitsRows,
        quarantinePayload: quarantinePayloadRows,
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
