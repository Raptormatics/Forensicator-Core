import { NextRequest, NextResponse } from "next/server";
import { prisma }      from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { guardDeletion } from "@/lib/cases/case-lock";

type Params = { params: Promise<{ id: string }> };

// ── GET /api/ram-analysis/uploads/[id] ─────────────────────────────────────
export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    await requireAuth(req);
    const { id } = params;

    const upload = await prisma.ramUpload.findUnique({
      where: { id },
      include: {
        uploadedBy:   { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
        case:         { select: { id: true, caseSeq: true, title: true, status: true, archivedAt: true } },
        _count:       { select: { processes: true, connections: true, findings: true, iocs: true } },
      },
    });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Paginated processes. Cap raised from 500 to 5000 — a process-tree view
    // needs every process to build correct parent/child edges, and the page
    // previously always fetched page 1 with the default limit=100 regardless
    // of the true count (upload.processCount), silently showing only the
    // first 100 processes on any image with more than that.
    const url   = new URL(req.url);
    const page  = parseInt(url.searchParams.get("page") ?? "1", 10);
    const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "100", 10), 5000);
    const skip  = (page - 1) * limit;

    const [processes, processTotal] = await Promise.all([
      prisma.ramProcess.findMany({
        where: { uploadId: id },
        orderBy: [{ pid: "asc" }],
        skip,
        take: limit,
      }),
      prisma.ramProcess.count({ where: { uploadId: id } }),
    ]);

    const connections = await prisma.ramNetworkConnection.findMany({
      where: { uploadId: id },
      orderBy: [{ createdAt: "asc" }],
      take: 1000,
    });

    // `severity` is free-text (critical/high/medium/low/info), so DB orderBy
    // would sort alphabetically — rank explicitly in JS instead.
    const RULE_SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const findings = (await prisma.ramFinding.findMany({
      where: { uploadId: id },
      orderBy: { matchCount: "desc" },
      include: {
        rule: { select: { id: true, name: true, tags: true, conditions: true } },
        yaraRule: { select: { id: true, name: true, tags: true } },
        malfindRegions: true,
        matches: { take: 1000 },
      },
    })).sort((a, b) =>
      (RULE_SEVERITY_RANK[b.severity] ?? -1) - (RULE_SEVERITY_RANK[a.severity] ?? -1) || b.matchCount - a.matchCount
    );

    const iocs = await prisma.ramIoc.findMany({
      where: { uploadId: id },
      orderBy: [{ count: "desc" }],
      take: 500,
    });

    return NextResponse.json({
      upload: { ...upload, fileSize: upload.fileSize.toString() },
      processes: { data: processes, total: processTotal, page, limit },
      connections,
      findings,
      iocs,
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── DELETE /api/ram-analysis/uploads/[id] ──────────────────────────────────
export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    await requireAuth(req);
    const locked = await guardDeletion({ ramUploadId: params.id }, "deleting this upload");
    if (locked) return locked;
    await prisma.ramUpload.delete({ where: { id: params.id } });
    return NextResponse.json({ ok: true });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
