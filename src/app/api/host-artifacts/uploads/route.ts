import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { prisma } from "@/lib/db/prisma";
import { requireAuth, orgWhere } from "@/lib/auth/api-guard";
import { getWinArtifactsDir, getWinArtifactsMaxUploadBytes } from "@/lib/settings/system";
import { getWinArtifactsQueue } from "@/lib/jobs/queues";
import type { WinArtifactFileRole } from "@/lib/windows-artifacts/types";
import { classifyForUpload } from "@/lib/windows-artifacts/collector-layout";
import { parseCollectionManifest, verifyAgainstManifest, type ParsedCollectionManifest } from "@/lib/windows-artifacts/collection-manifest";
import { notArchived } from "@/lib/cases/archive";
import { canAccessOrg } from "@/lib/auth/org-access";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Combined across every file in one upload — see getWinArtifactsMaxUploadBytes()
// for the DB-override/env-var/default chain (5GB default; configurable from
// Settings > General without a restart).

// Form-field name -> artifact role, for the single-file-per-collection roles.
const SINGLE_FILE_FIELDS: { field: string; role: WinArtifactFileRole }[] = [
  { field: "system", role: "system_hive" },
  { field: "software", role: "software_hive" },
  { field: "security", role: "security_hive" },
  { field: "sam", role: "sam_hive" },
  { field: "default", role: "default_hive" },
  { field: "amcache", role: "amcache_hive" },
  { field: "mft", role: "mft" },
  { field: "srudb", role: "srum_db" },
  { field: "searchedb", role: "search_edb" },
  { field: "qmgr0", role: "bits_queue" },
  { field: "qmgr1", role: "bits_queue" },
];

// Which SINGLE_FILE_FIELDS/per-profile fields can carry an optional
// <field>Log1/<field>Log2 pair (the hive's own .LOG1/.LOG2 transaction
// logs) — only registry hives have these, not $MFT/SRUDB.dat/etc.
const HIVE_FIELDS_WITH_LOGS = new Set(["system", "software", "security", "sam", "default", "amcache"]);

function isUploadedFile(v: FormDataEntryValue | null): v is File {
  return !!v && typeof v !== "string" && "arrayBuffer" in v;
}

// Streams the hash instead of buffering the whole file — used for staged
// (chunk-uploaded) files, which can be multi-GB; see
// src/app/api/host-artifacts/uploads/staged/**. No resume case here
// (unlike chunked-upload-state.ts's getOrRebuildHash) since this only ever
// runs once, after the staged file is already fully on disk.
async function sha256OfFile(filePath: string): Promise<string> {
  const hash = crypto.createHash("sha256");
  await new Promise<void>((resolve, reject) => {
    const stream = fs.createReadStream(filePath);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", resolve);
    stream.on("error", reject);
  });
  return hash.digest("hex");
}

// A real uploaded log1/log2 file; filters out the zero-byte placeholder
// the upload page sends for a profile row with no log file, to keep
// getAll()'s positional zip against the main file array aligned (a
// skipped `form.append` for an absent log would desync indices otherwise).
function isRealUploadedFile(v: FormDataEntryValue | null): v is File {
  return isUploadedFile(v) && v.size > 0;
}

// ── GET /api/host-artifacts/uploads ──────────────────────────────────────
export async function GET(req: NextRequest) {
  try {
    const actor = await requireAuth(req);
    const where = orgWhere(actor);

    // Archived uploads (or ones in an archived case) are on the Archive page.
    const uploads = await prisma.windowsArtifactUpload.findMany({
      where: { ...where, ...notArchived() },
      orderBy: { createdAt: "desc" },
      take: 100,
      select: {
        id: true, hostname: true, notes: true, findingCount: true,
        createdAt: true, updatedAt: true,
        uploadedBy: { select: { email: true, name: true } },
        case: { select: { id: true, title: true, caseSeq: true, status: true, archivedAt: true } },
        files: { select: { id: true, role: true, filename: true, status: true, findingCount: true } },
      },
    });

    return NextResponse.json({ uploads });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── POST /api/host-artifacts/uploads ─────────────────────────────────────
// Accepts a multi-file bundle in one POST — a real triage collection from
// one host gathers SYSTEM/SOFTWARE/NTUSER.DAT(xN)/Amcache.hve together, so
// this is one upload action, not one-file-per-upload like RAM/PCAP today.
// Each file becomes its own WindowsArtifactFile, queued as its own job —
// one bad hive in the bundle doesn't block the rest.
export async function POST(req: NextRequest) {
  try {
    const actor = await requireAuth(req);
    const formData = await req.formData();

    const hostname = String(formData.get("hostname") ?? "").trim() || null;
    const notes = String(formData.get("notes") ?? "").trim() || null;
    const caseId = String(formData.get("caseId") ?? "").trim() || null;

    if (!caseId) {
      return NextResponse.json({ error: "missing_case", message: "Every artifact upload must be linked to a case. Select or create one before uploading." }, { status: 400 });
    }

    const kase = await prisma.case.findUnique({ where: { id: caseId }, select: { id: true, status: true, organizationId: true } });
    // Another organization's case is treated as nonexistent.
    if (!kase || !canAccessOrg(actor, kase.organizationId)) {
      return NextResponse.json({ error: "invalid_case", message: "The specified case does not exist." }, { status: 400 });
    }
    if (kase.status === "closed") {
      return NextResponse.json({ error: "case_closed", message: "This case is closed and cannot accept new uploads. Reopen it first." }, { status: 403 });
    }

    type PendingFile = {
      role: WinArtifactFileRole; profileName: string | null; relativePath?: string | null;
      journalMetadataText?: string | null; log1File?: File | null; log2File?: File | null;
      // Collector-folder mode only (see below): where this copy came from,
      // and its path relative to WindowsArtifacts for manifest verification.
      provenance?: string | null; manifestPath?: string | null;
      // Exactly one of these is set. A plain multipart File for every field
      // except the SINGLE_FILE_FIELDS and collector-folder entries, which may instead reference an
      // already chunk-uploaded file (see src/app/api/host-artifacts/
      // uploads/staged/** — large single files like $MFT can't safely go
      // through formData() at all, see that route's own doc comment).
      file?: File;
      stagedFile?: { id: string; storagePath: string; totalBytes: bigint; filename: string };
    };
    const pending: PendingFile[] = [];
    let manifest: ParsedCollectionManifest | null = null;

    // ── Collector-folder mode ────────────────────────────────────────────
    // The upload page's "Collector folder" picker sends every file under
    // the collector's artifacts folder as `cf` + `cfPath` (its path
    // relative to the host's `artifacts` folder, e.g.
    // "WindowsArtifacts/Registry/SYSTEM"), or — for files large enough to
    // need chunked staging — `cfStagedId` + `cfStagedPath`. Roles are
    // re-derived here from the path via the same classifier the page used
    // (collector-layout.ts), never trusted from the client; hives pick up
    // their .LOG1/.LOG2 and $J its fsutil metadata by groupKey; the
    // collector's CollectionManifest is parsed for hash verification.
    // Coexists with the per-role fields below — both may be sent at once.
    type CollectorEntry = { relPath: string; file?: File; staged?: PendingFile["stagedFile"] };
    const collectorEntries: CollectorEntry[] = [];
    const cfFiles = formData.getAll("cf");
    const cfPaths = formData.getAll("cfPath").map((v) => String(v));
    cfFiles.forEach((f, i) => { if (isUploadedFile(f) && cfPaths[i]) collectorEntries.push({ relPath: cfPaths[i], file: f }); });
    const cfStagedIds = formData.getAll("cfStagedId").map((v) => String(v).trim());
    const cfStagedPaths = formData.getAll("cfStagedPath").map((v) => String(v));
    for (let i = 0; i < cfStagedIds.length; i++) {
      const staged = await prisma.windowsArtifactStagedFile.findUnique({ where: { id: cfStagedIds[i] } });
      if (!staged || staged.uploadedById !== actor.id || staged.status !== "staged") {
        return NextResponse.json(
          { error: "invalid_staged_file", message: `The staged upload for "${cfStagedPaths[i] ?? cfStagedIds[i]}" was not found or has already been used/expired. Re-select the folder and try again.` },
          { status: 400 }
        );
      }
      collectorEntries.push({ relPath: cfStagedPaths[i] ?? staged.filename, staged: { id: staged.id, storagePath: staged.storagePath, totalBytes: staged.totalBytes, filename: staged.filename } });
    }

    if (collectorEntries.length > 0) {
      const byGroup = new Map<string, PendingFile>();
      const sidecars: { entry: CollectorEntry; sidecar: "log1" | "log2" | "usn_metadata"; attachTo: string }[] = [];
      for (const entry of collectorEntries) {
        const c = classifyForUpload(entry.relPath);
        if (c.kind === "manifest" && entry.file) {
          try {
            manifest = parseCollectionManifest(Buffer.from(await entry.file.arrayBuffer()));
          } catch (err) {
            return NextResponse.json({ error: "invalid_manifest", message: `CollectionManifest could not be parsed: ${err instanceof Error ? err.message : String(err)}` }, { status: 400 });
          }
        } else if (c.kind === "artifact") {
          byGroup.set(c.groupKey, {
            role: c.role, profileName: c.profileName, provenance: c.provenance,
            relativePath: entry.relPath,
            // The manifest covers WindowsArtifacts (or LinuxArtifacts), keyed relative to it.
            manifestPath: /^(windows|linux)artifacts\//i.test(entry.relPath) ? entry.relPath.replace(/^[^/]+\//, "") : null,
            file: entry.file, stagedFile: entry.staged,
          });
        } else if (c.kind === "sidecar") {
          sidecars.push({ entry, sidecar: c.sidecar, attachTo: c.attachTo });
        }
        // "unsupported"/"ignored" are listed client-side and simply not uploaded;
        // "log" (Linux collector logs) the page sends to Log Analysis instead.
      }
      for (const { entry, sidecar, attachTo } of sidecars) {
        const owner = byGroup.get(attachTo);
        if (!owner || !entry.file) continue; // sidecars are always small — never staged
        if (sidecar === "log1") owner.log1File = entry.file;
        else if (sidecar === "log2") owner.log2File = entry.file;
        else owner.journalMetadataText = await entry.file.text();
      }
      pending.push(...byGroup.values());
    }

    for (const { field, role } of SINGLE_FILE_FIELDS) {
      const stagedId = String(formData.get(`${field}StagedId`) ?? "").trim();
      let entry: PendingFile | null = null;

      if (stagedId) {
        const staged = await prisma.windowsArtifactStagedFile.findUnique({ where: { id: stagedId } });
        if (!staged || staged.uploadedById !== actor.id || staged.status !== "staged") {
          return NextResponse.json(
            { error: "invalid_staged_file", message: `The staged upload for "${field}" was not found or has already been used/expired. Re-select the file and try again.` },
            { status: 400 }
          );
        }
        entry = { role, profileName: null, stagedFile: { id: staged.id, storagePath: staged.storagePath, totalBytes: staged.totalBytes, filename: staged.filename } };
      } else {
        const f = formData.get(field);
        if (isUploadedFile(f)) entry = { role, file: f, profileName: null };
      }

      if (entry) {
        if (HIVE_FIELDS_WITH_LOGS.has(field)) {
          const log1 = formData.get(`${field}Log1`);
          const log2 = formData.get(`${field}Log2`);
          entry.log1File = isUploadedFile(log1) ? log1 : null;
          entry.log2File = isUploadedFile(log2) ? log2 : null;
        }
        pending.push(entry);
      }
    }

    const ntuserFiles = formData.getAll("ntuser").filter(isUploadedFile);
    const ntuserNames = formData.getAll("ntuserProfileName").map((v) => String(v));
    // NOT pre-filtered — a row with no log sends a zero-byte placeholder
    // (see upload/page.tsx) specifically to keep these positionally
    // aligned with ntuserFiles; only check isRealUploadedFile per-index.
    const ntuserLog1sRaw = formData.getAll("ntuserLog1");
    const ntuserLog2sRaw = formData.getAll("ntuserLog2");
    ntuserFiles.forEach((file, i) => pending.push({
      role: "ntuser_hive", file, profileName: ntuserNames[i]?.trim() || null,
      log1File: isRealUploadedFile(ntuserLog1sRaw[i] ?? null) ? ntuserLog1sRaw[i] as File : null,
      log2File: isRealUploadedFile(ntuserLog2sRaw[i] ?? null) ? ntuserLog2sRaw[i] as File : null,
    }));

    const usrclassFiles = formData.getAll("usrclass").filter(isUploadedFile);
    const usrclassNames = formData.getAll("usrclassProfileName").map((v) => String(v));
    const usrclassLog1sRaw = formData.getAll("usrclassLog1");
    const usrclassLog2sRaw = formData.getAll("usrclassLog2");
    usrclassFiles.forEach((file, i) => pending.push({
      role: "usrclass_hive", file, profileName: usrclassNames[i]?.trim() || null,
      log1File: isRealUploadedFile(usrclassLog1sRaw[i] ?? null) ? usrclassLog1sRaw[i] as File : null,
      log2File: isRealUploadedFile(usrclassLog2sRaw[i] ?? null) ? usrclassLog2sRaw[i] as File : null,
    }));

    // Prefetch .pf files — a whole folder's worth collected at once, no
    // per-file profile pairing needed (unlike NTUSER, which is per-user).
    const prefetchFiles = formData.getAll("prefetch").filter(isUploadedFile);
    prefetchFiles.forEach((file) => pending.push({ role: "prefetch", file, profileName: null }));

    // LNK / Jump List files — the collector spreads these across several
    // subfolders (LNK under Desktop/Links/OneDrive/etc., Jump Lists under
    // one subfolder per user profile), so the upload form may send a
    // relative path (via its own folder picker) alongside each file —
    // kept as the stored filename instead of collapsing to the bare name,
    // which also avoids same-named files from different folders colliding.
    const lnkFiles = formData.getAll("lnk").filter(isUploadedFile);
    const lnkPaths = formData.getAll("lnkRelativePath").map((v) => String(v));
    lnkFiles.forEach((file, i) => pending.push({ role: "lnk", file, profileName: null, relativePath: lnkPaths[i] || null }));

    const jumplistAutomaticFiles = formData.getAll("jumplistAutomatic").filter(isUploadedFile);
    const jumplistAutomaticPaths = formData.getAll("jumplistAutomaticRelativePath").map((v) => String(v));
    jumplistAutomaticFiles.forEach((file, i) => pending.push({ role: "jumplist_automatic", file, profileName: null, relativePath: jumplistAutomaticPaths[i] || null }));

    const jumplistCustomFiles = formData.getAll("jumplistCustom").filter(isUploadedFile);
    const jumplistCustomPaths = formData.getAll("jumplistCustomRelativePath").map((v) => String(v));
    jumplistCustomFiles.forEach((file, i) => pending.push({ role: "jumplist_custom", file, profileName: null, relativePath: jumplistCustomPaths[i] || null }));

    // $UsnJrnl:$J — the collector's own fsutil usn queryjournal sidecar
    // (if gathered) is volume-level context, not a separate parseable
    // artifact, so it rides along on the SAME WindowsArtifactFile row
    // (journalMetadataText) rather than becoming its own role/upload field.
    const usnjrnlFile = formData.get("usnjrnl");
    if (isUploadedFile(usnjrnlFile)) {
      const metadataFile = formData.get("usnJournalMetadata");
      const journalMetadataText = isUploadedFile(metadataFile) ? await metadataFile.text() : null;
      pending.push({ role: "usnjrnl", file: usnjrnlFile, profileName: null, journalMetadataText });
    }

    // Windows Error Reporting — reports and crash dumps are each spread
    // across a System folder and per-profile folders, same "folder-picker
    // relative path preserved as the stored filename" convention as LNK.
    const werReportFiles = formData.getAll("werReport").filter(isUploadedFile);
    const werReportPaths = formData.getAll("werReportRelativePath").map((v) => String(v));
    werReportFiles.forEach((file, i) => pending.push({ role: "wer_report", file, profileName: null, relativePath: werReportPaths[i] || null }));

    const werDumpFiles = formData.getAll("werDump").filter(isUploadedFile);
    const werDumpPaths = formData.getAll("werDumpRelativePath").map((v) => String(v));
    werDumpFiles.forEach((file, i) => pending.push({ role: "wer_dump", file, profileName: null, relativePath: werDumpPaths[i] || null }));

    // Recycle Bin $I files — one subfolder per SID, same relative-path
    // preservation so the SID is recoverable from the stored filename.
    const recycleBinFiles = formData.getAll("recyclebin").filter(isUploadedFile);
    const recycleBinPaths = formData.getAll("recyclebinRelativePath").map((v) => String(v));
    recycleBinFiles.forEach((file, i) => pending.push({ role: "recycle_bin", file, profileName: null, relativePath: recycleBinPaths[i] || null }));

    // Notification database — one per user profile, same ProfileFileList
    // pairing convention as NTUSER.DAT/UsrClass.dat.
    const notificationFiles = formData.getAll("notification").filter(isUploadedFile);
    const notificationNames = formData.getAll("notificationProfileName").map((v) => String(v));
    notificationFiles.forEach((file, i) => pending.push({ role: "notification_db", file, profileName: notificationNames[i]?.trim() || null }));

    // Defender quarantine — Entries (metadata) and ResourceData (payload)
    // are uploaded as two independent roles; no relational link between a
    // specific Entries file and a specific ResourceData file is assumed
    // (see windows-artifacts plan's Decisions on why that's deliberate).
    const quarantineEntryFiles = formData.getAll("quarantineEntries").filter(isUploadedFile);
    const quarantineEntryPaths = formData.getAll("quarantineEntriesRelativePath").map((v) => String(v));
    quarantineEntryFiles.forEach((file, i) => pending.push({ role: "quarantine_entry", file, profileName: null, relativePath: quarantineEntryPaths[i] || null }));

    const quarantineResourceFiles = formData.getAll("quarantineResources").filter(isUploadedFile);
    const quarantineResourcePaths = formData.getAll("quarantineResourcesRelativePath").map((v) => String(v));
    quarantineResourceFiles.forEach((file, i) => pending.push({ role: "quarantine_resource", file, profileName: null, relativePath: quarantineResourcePaths[i] || null }));

    // Windows Timeline — one per user profile, same ProfileFileList
    // pairing convention as the Notification database above.
    const timelineFiles = formData.getAll("timeline").filter(isUploadedFile);
    const timelineNames = formData.getAll("timelineProfileName").map((v) => String(v));
    timelineFiles.forEach((file, i) => pending.push({ role: "timeline_db", file, profileName: timelineNames[i]?.trim() || null }));

    if (pending.length === 0) {
      return NextResponse.json({ error: "no_files", message: "Upload at least one artifact file (SYSTEM, SOFTWARE, NTUSER.DAT, or Amcache.hve), or a collector WindowsArtifacts folder." }, { status: 400 });
    }

    const totalBytes = pending.reduce((sum, p) => sum + (p.file ? p.file.size : Number(p.stagedFile!.totalBytes)), 0);
    const maxTotalBytes = await getWinArtifactsMaxUploadBytes();
    if (totalBytes > maxTotalBytes) {
      const maxMb = (maxTotalBytes / 1024 / 1024).toFixed(0);
      return NextResponse.json({ error: "file_too_large", message: `Combined upload exceeds the ${maxMb} MB limit for one collection.` }, { status: 413 });
    }

    const upload = await prisma.windowsArtifactUpload.create({
      data: {
        hostname, notes,
        collectionManifest: manifest ? (manifest.stored as unknown as object) : undefined,
        uploadedById: actor.id,
        organizationId: kase.organizationId,
        caseId,
      },
    });

    const dir = await getWinArtifactsDir();
    fs.mkdirSync(dir, { recursive: true });
    const queue = getWinArtifactsQueue();

    const createdFiles = [];
    for (const p of pending) {
      // Staged (chunk-uploaded) files are already fully on disk — stream
      // the hash and rename into place instead of ever buffering a
      // potentially multi-GB file in memory, same reasoning as the staged
      // routes themselves.
      const filename = p.relativePath || (p.file ? p.file.name : p.stagedFile!.filename);
      const fileSize = p.file ? p.file.size : Number(p.stagedFile!.totalBytes);
      const buffer = p.file ? Buffer.from(await p.file.arrayBuffer()) : null;
      const sha256 = buffer ? crypto.createHash("sha256").update(buffer).digest("hex") : await sha256OfFile(p.stagedFile!.storagePath);
      const integrity = verifyAgainstManifest(manifest, p.manifestPath ?? null, sha256);

      const fileRow = await prisma.windowsArtifactFile.create({
        data: {
          uploadId: upload.id,
          role: p.role,
          filename,
          fileSize,
          sha256,
          status: "queued",
          profileName: p.profileName,
          journalMetadataText: p.journalMetadataText ?? null,
          provenance: p.provenance ?? null,
          manifestSha256: integrity.manifestSha256,
          integrityStatus: integrity.integrityStatus,
        },
      });

      const ext = path.extname(filename);
      const storagePath = path.join(dir, `${fileRow.id}${ext}`);
      if (buffer) {
        fs.writeFileSync(storagePath, buffer);
      } else {
        await fs.promises.rename(p.stagedFile!.storagePath, storagePath);
        await prisma.windowsArtifactStagedFile.update({ where: { id: p.stagedFile!.id }, data: { status: "consumed" } });
      }

      // This hive's own .LOG1/.LOG2 transaction logs, when provided —
      // written alongside the hive under the same fileRow.id so
      // registry-parse.py can find and replay them (see processor.ts).
      let log1StoragePath: string | null = null;
      let log2StoragePath: string | null = null;
      if (p.log1File) {
        log1StoragePath = path.join(dir, `${fileRow.id}.log1`);
        fs.writeFileSync(log1StoragePath, Buffer.from(await p.log1File.arrayBuffer()));
      }
      if (p.log2File) {
        log2StoragePath = path.join(dir, `${fileRow.id}.log2`);
        fs.writeFileSync(log2StoragePath, Buffer.from(await p.log2File.arrayBuffer()));
      }

      const updated = await prisma.windowsArtifactFile.update({
        where: { id: fileRow.id },
        data: { storagePath, log1StoragePath, log2StoragePath },
      });
      createdFiles.push(updated);
    }

    // Queue only once every row and file exists: some jobs read a sibling
    // file from the same collection (an .odl needs the general.keystore from
    // its folder), and queuing as we go let a job start before its sibling
    // had been written.
    for (let i = 0; i < createdFiles.length; i++) {
      const job = await queue.add("process-winartifact-file", { winArtifactFileId: createdFiles[i].id });
      createdFiles[i] = await prisma.windowsArtifactFile.update({ where: { id: createdFiles[i].id }, data: { jobId: job.id ?? null } });
    }

    return NextResponse.json({
      // fileSize is BigInt — not JSON-serializable as-is.
      upload: { ...upload, files: createdFiles.map((f) => ({ ...f, fileSize: f.fileSize.toString() })) },
    }, { status: 201 });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[windows-artifacts/uploads] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
