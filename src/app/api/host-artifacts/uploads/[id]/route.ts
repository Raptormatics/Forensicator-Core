import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { guardDeletion } from "@/lib/cases/case-lock";
import { actorOr401, guardOrgAccess } from "@/lib/auth/org-access";

type Params = { params: Promise<{ id: string }> };

const ROW_CAP = 2000; // per artifact type, across all files in the collection — generous for a single-host triage bundle

// Generic records (Stage-2 Windows types and every Linux type), capped per
// kind rather than overall — one large kind (a Linux filesystem timeline is
// tens of thousands of rows) must not crowd out the rest. Within a kind,
// records carrying `findings` (Linux traits) come first, so the suspicious
// ones are always in the browsable slice.
async function loadArtifactRecords(fileIds: string[]) {
  const groups = await prisma.artifactRecordEntry.groupBy({ by: ["kind"], where: { fileId: { in: fileIds } }, _count: { _all: true } });
  const perKind = await Promise.all(groups.map(async (g) => {
    const where = { fileId: { in: fileIds }, kind: g.kind };
    const flagged = await prisma.artifactRecordEntry.findMany({
      where: { ...where, details: { path: ["findings"], not: "" } },
      orderBy: { timestamp: "desc" }, take: ROW_CAP,
    });
    const rest = flagged.length < ROW_CAP && flagged.length < g._count._all
      ? await prisma.artifactRecordEntry.findMany({
          where: { ...where, id: { notIn: flagged.map((r) => r.id) } },
          orderBy: { timestamp: "desc" }, take: ROW_CAP - flagged.length,
        })
      : [];
    return [...flagged, ...rest];
  }));
  return {
    rows: perKind.flat(),
    counts: Object.fromEntries(groups.map((g) => [g.kind, g._count._all])),
  };
}

// ── GET /api/host-artifacts/uploads/[id] ─────────────────────────────────
// Rolls up every child file's parsed rows + findings into one response —
// registry-hive row counts are modest enough (hundreds to low thousands)
// that this comfortably fits one fetch, unlike PCAP's paginated conversations.
export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  const orgActor = await actorOr401(req);
  if (orgActor instanceof NextResponse) return orgActor;
  const orgDenied = await guardOrgAccess(orgActor, { windowsArtifactUploadId: params.id });
  if (orgDenied) return orgDenied;
  try {
    await requireAuth(req);
    const { id } = params;

    const upload = await prisma.windowsArtifactUpload.findUnique({
      where: { id },
      include: {
        uploadedBy: { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
        case: { select: { id: true, title: true, caseSeq: true, status: true, archivedAt: true } },
        files: { orderBy: { createdAt: "asc" } },
      },
    });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    const fileIds = upload.files.map((f) => f.id);

    const [
      shimcache, amcache, userAssist, bam, autoruns, prefetch, lnk, jumpList, shellbags, mft, usnJrnl, srum,
      werReports, werDumps, recycleBin, notifications, searchIndex, quarantineEntries, quarantinePayloads, bitsJobs,
      timeline, registryPlugins, artifactRecords,
      findings,
    ] = await Promise.all([
      prisma.shimcacheEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { order: "asc" }, take: ROW_CAP }),
      prisma.amcacheEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { createdAt: "asc" }, take: ROW_CAP }),
      prisma.userAssistEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { lastExecuted: "desc" }, take: ROW_CAP }),
      prisma.bamEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { lastExecuted: "desc" }, take: ROW_CAP }),
      prisma.autorunEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { category: "asc" }, take: ROW_CAP }),
      prisma.prefetchEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { firstRunTime: "desc" }, take: ROW_CAP }),
      prisma.lnkEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { createdAt: "asc" }, take: ROW_CAP }),
      prisma.jumpListEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { accessRank: "asc" }, take: ROW_CAP }),
      prisma.shellbagEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { path: "asc" }, take: ROW_CAP }),
      // $MFT/$UsnJrnl:$J can run into the hundreds of thousands to
      // millions of rows — ROW_CAP still applies for this browsable tab
      // (every row is still in the DB and still ran through the rule
      // engine regardless; see processor.ts), same scope decision as
      // every other artifact type here, just a more consequential one.
      prisma.mftEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { mftEntryNumber: "asc" }, take: ROW_CAP }),
      prisma.usnJrnlEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { usn: "asc" }, take: ROW_CAP }),
      prisma.srumEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { timestamp: "desc" }, take: ROW_CAP }),
      prisma.werReportEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { eventTime: "desc" }, take: ROW_CAP }),
      prisma.werDumpEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { createdAt: "desc" }, take: ROW_CAP }),
      prisma.recycleBinEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { deletedTime: "desc" }, take: ROW_CAP }),
      prisma.notificationEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { arrivalTime: "desc" }, take: ROW_CAP }),
      // Windows Search can realistically index hundreds of thousands of
      // files — same ROW_CAP-limited browsable-tab convention as
      // $MFT/$UsnJrnl, every row is still in the DB regardless.
      prisma.searchIndexEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { recordIndex: "asc" }, take: ROW_CAP }),
      prisma.defenderQuarantineEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { timestamp: "desc" }, take: ROW_CAP }),
      prisma.defenderQuarantinePayload.findMany({ where: { fileId: { in: fileIds } }, orderBy: { createdAt: "desc" }, take: ROW_CAP }),
      prisma.bitsJobEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { ctime: "desc" }, take: ROW_CAP }),
      prisma.timelineActivityEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { startTime: "desc" }, take: ROW_CAP }),
      // Spans many plugins (installed programs, IFEO, network profiles,
      // SAM accounts, ...) across every hive in the collection, including
      // historical copies — a higher cap than the single-artifact tabs.
      prisma.registryPluginEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: [{ plugin: "asc" }, { timestamp: "desc" }], take: ROW_CAP * 5 }),
      // Stage-2 generic records (WMI, Defender history, application
      // artifacts, $LogFile, payloads, memory indicators, collector extras)
      // across every file — every row is in the DB and went through the
      // rule engine; this is only the browsable slice.
      loadArtifactRecords(fileIds),
      prisma.windowsArtifactFinding.findMany({
        where: { fileId: { in: fileIds } },
        orderBy: { matchCount: "desc" },
        include: { rule: { select: { id: true, name: true, tags: true } } },
      }),
    ]);

    const RULE_SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    findings.sort((a, b) => (RULE_SEVERITY_RANK[b.severity] ?? -1) - (RULE_SEVERITY_RANK[a.severity] ?? -1) || b.matchCount - a.matchCount);

    return NextResponse.json({
      // fileSize is BigInt (a busy workstation's $MFT alone can exceed
      // Int's ~2.1GB ceiling) — not JSON-serializable as-is, same
      // stringify convention as every other bigint field in this response.
      upload: { ...upload, files: upload.files.map((f) => ({ ...f, fileSize: f.fileSize.toString() })) },
      shimcache: shimcache.map((r) => ({ ...r, fileId: r.fileId })),
      amcache: amcache.map((r) => ({ ...r, fileSizeBytes: r.fileSizeBytes?.toString() ?? null })),
      userAssist,
      bam,
      autoruns,
      prefetch,
      lnk,
      jumpList,
      shellbags,
      mft: mft.map((r) => ({ ...r, fileSize: r.fileSize?.toString() ?? null })),
      usnJrnl: usnJrnl.map((r) => ({ ...r, usn: r.usn.toString() })),
      srum,
      werReports,
      werDumps,
      recycleBin: recycleBin.map((r) => ({ ...r, fileSizeBytes: r.fileSizeBytes?.toString() ?? null })),
      notifications,
      searchIndex,
      quarantineEntries,
      quarantinePayloads: quarantinePayloads.map((r) => ({ ...r, decryptedSizeBytes: r.decryptedSizeBytes?.toString() ?? null })),
      timeline,
      registryPlugins,
      artifactRecords: artifactRecords.rows,
      artifactRecordCounts: artifactRecords.counts,
      bitsJobs: bitsJobs.map((r) => ({
        ...r,
        downloadSizeBytes: r.downloadSizeBytes?.toString() ?? null,
        transferSizeBytes: r.transferSizeBytes?.toString() ?? null,
      })),
      findings,
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── DELETE /api/host-artifacts/uploads/[id] ──────────────────────────────
export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  const orgActor = await actorOr401(req);
  if (orgActor instanceof NextResponse) return orgActor;
  const orgDenied = await guardOrgAccess(orgActor, { windowsArtifactUploadId: params.id });
  if (orgDenied) return orgDenied;
  try {
    await requireAuth(req);
    const locked = await guardDeletion({ windowsArtifactUploadId: params.id }, "deleting this upload");
    if (locked) return locked;
    const { id } = params;

    const upload = await prisma.windowsArtifactUpload.findUnique({
      where: { id },
      include: {
        files: {
          select: {
            storagePath: true,
            // A hive's own .LOG1/.LOG2 transaction logs are written to
            // their own paths too — needs cleanup here or they're
            // orphaned once the DB row is gone, same reasoning as
            // quarantinePayloads below.
            log1StoragePath: true,
            log2StoragePath: true,
            // Defender quarantine payloads write a SECOND file to disk
            // (the decrypted bytes) at a path independent of the
            // uploaded file's own storagePath — needs its own cleanup
            // here or it's orphaned once the DB row is gone.
            quarantinePayloads: { select: { decryptedStoragePath: true } },
          },
        },
      },
    });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    await prisma.windowsArtifactUpload.delete({ where: { id } }); // cascades to files/entries/findings

    for (const f of upload.files) {
      if (f.storagePath) {
        try { fs.unlinkSync(f.storagePath); } catch { /* best-effort — DB row is already gone either way */ }
      }
      if (f.log1StoragePath) {
        try { fs.unlinkSync(f.log1StoragePath); } catch { /* best-effort */ }
      }
      if (f.log2StoragePath) {
        try { fs.unlinkSync(f.log2StoragePath); } catch { /* best-effort */ }
      }
      for (const payload of f.quarantinePayloads) {
        if (payload.decryptedStoragePath) {
          try { fs.unlinkSync(payload.decryptedStoragePath); } catch { /* best-effort */ }
        }
      }
    }

    return NextResponse.json({ success: true });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
