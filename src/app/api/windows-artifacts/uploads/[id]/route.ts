import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";

type Params = { params: Promise<{ id: string }> };

const ROW_CAP = 2000; // per artifact type, across all files in the collection — generous for a single-host triage bundle

// ── GET /api/windows-artifacts/uploads/[id] ─────────────────────────────────
// Rolls up every child file's parsed rows + findings into one response —
// registry-hive row counts are modest enough (hundreds to low thousands)
// that this comfortably fits one fetch, unlike PCAP's paginated conversations.
export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    await requireAuth(req);
    const { id } = params;

    const upload = await prisma.windowsArtifactUpload.findUnique({
      where: { id },
      include: {
        uploadedBy: { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
        case: { select: { id: true, title: true, caseSeq: true } },
        files: { orderBy: { createdAt: "asc" } },
      },
    });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    const fileIds = upload.files.map((f) => f.id);

    const [shimcache, amcache, userAssist, bam, autoruns, prefetch, lnk, jumpList, shellbags, findings] = await Promise.all([
      prisma.shimcacheEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { order: "asc" }, take: ROW_CAP }),
      prisma.amcacheEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { createdAt: "asc" }, take: ROW_CAP }),
      prisma.userAssistEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { lastExecuted: "desc" }, take: ROW_CAP }),
      prisma.bamEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { lastExecuted: "desc" }, take: ROW_CAP }),
      prisma.autorunEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { category: "asc" }, take: ROW_CAP }),
      prisma.prefetchEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { firstRunTime: "desc" }, take: ROW_CAP }),
      prisma.lnkEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { createdAt: "asc" }, take: ROW_CAP }),
      prisma.jumpListEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { accessRank: "asc" }, take: ROW_CAP }),
      prisma.shellbagEntry.findMany({ where: { fileId: { in: fileIds } }, orderBy: { path: "asc" }, take: ROW_CAP }),
      prisma.windowsArtifactFinding.findMany({
        where: { fileId: { in: fileIds } },
        orderBy: { matchCount: "desc" },
        include: { rule: { select: { id: true, name: true, tags: true } } },
      }),
    ]);

    const RULE_SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    findings.sort((a, b) => (RULE_SEVERITY_RANK[b.severity] ?? -1) - (RULE_SEVERITY_RANK[a.severity] ?? -1) || b.matchCount - a.matchCount);

    return NextResponse.json({
      upload,
      shimcache: shimcache.map((r) => ({ ...r, fileId: r.fileId })),
      amcache: amcache.map((r) => ({ ...r, fileSizeBytes: r.fileSizeBytes?.toString() ?? null })),
      userAssist,
      bam,
      autoruns,
      prefetch,
      lnk,
      jumpList,
      shellbags,
      findings,
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── DELETE /api/windows-artifacts/uploads/[id] ──────────────────────────────
export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    await requireAuth(req);
    const { id } = params;

    const upload = await prisma.windowsArtifactUpload.findUnique({
      where: { id },
      include: { files: { select: { storagePath: true } } },
    });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    await prisma.windowsArtifactUpload.delete({ where: { id } }); // cascades to files/entries/findings

    for (const f of upload.files) {
      if (f.storagePath) {
        try { fs.unlinkSync(f.storagePath); } catch { /* best-effort — DB row is already gone either way */ }
      }
    }

    return NextResponse.json({ success: true });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
