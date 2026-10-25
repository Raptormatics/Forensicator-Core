import { NextRequest, NextResponse } from "next/server";
import { prisma }       from "@/lib/db/prisma";
import { requireAuth }  from "@/lib/auth/api-guard";
import { guardDeletion } from "@/lib/cases/case-lock";
import { actorOr401, guardOrgAccess } from "@/lib/auth/org-access";

type Params = { params: Promise<{ id: string }> };

// ── GET /api/log-analysis/uploads/[id] ─────────────────────────────────────
export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  const orgActor = await actorOr401(req);
  if (orgActor instanceof NextResponse) return orgActor;
  const orgDenied = await guardOrgAccess(orgActor, { logUploadId: params.id });
  if (orgDenied) return orgDenied;
  try {
    await requireAuth(req);
    const { id } = params;

    const upload = await prisma.logUpload.findUnique({
      where: { id },
      include: {
        uploadedBy:   { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
        case:         { select: { id: true, caseSeq: true, title: true, status: true, archivedAt: true } },
        _count:       { select: { events: true, findings: true, iocs: true } },
      },
    });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Paginated events
    const url    = new URL(req.url);
    const page   = parseInt(url.searchParams.get("page") ?? "1", 10);
    const limit  = Math.min(parseInt(url.searchParams.get("limit") ?? "100", 10), 500);
    const search = url.searchParams.get("q") ?? "";
    const skip   = (page - 1) * limit;

    const eventWhere = search
      ? {
          uploadId: id,
          OR: [
            { srcIp:     { contains: search, mode: "insensitive" as const } },
            { dstIp:     { contains: search, mode: "insensitive" as const } },
            { username:  { contains: search, mode: "insensitive" as const } },
            { process:   { contains: search, mode: "insensitive" as const } },
            { message:   { contains: search, mode: "insensitive" as const } },
            { url:       { contains: search, mode: "insensitive" as const } },
            { eventType: { contains: search, mode: "insensitive" as const } },
          ],
        }
      : { uploadId: id };

    const [events, total] = await Promise.all([
      prisma.logEvent.findMany({
        where: eventWhere,
        orderBy: [{ lineNumber: "asc" }],
        skip,
        take: limit,
        select: {
          id: true, lineNumber: true, timestamp: true, sourceApp: true,
          eventType: true, srcIp: true, dstIp: true, srcPort: true, dstPort: true,
          username: true, domain: true, process: true, commandLine: true,
          filePath: true, fileName: true, hashMd5: true, hashSha1: true, hashSha256: true,
          url: true, httpMethod: true, statusCode: true, userAgent: true,
          message: true, normalized: true,
        },
      }),
      prisma.logEvent.count({ where: eventWhere }),
    ]);

    // `severity` is free-text (critical/high/medium/low/info), so DB orderBy
    // would sort alphabetically — rank explicitly in JS instead.
    const RULE_SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const findings = (await prisma.logFinding.findMany({
      where: { uploadId: id },
      orderBy: { eventCount: "desc" },
      include: { rule: { select: { id: true, name: true, tags: true } } },
    })).sort((a, b) =>
      (RULE_SEVERITY_RANK[b.severity] ?? -1) - (RULE_SEVERITY_RANK[a.severity] ?? -1) || b.eventCount - a.eventCount
    );

    const iocs = await prisma.logIoc.findMany({
      where: { uploadId: id },
      orderBy: [{ count: "desc" }],
      take: 500,
    });

    return NextResponse.json({
      upload,
      events: { data: events, total, page, limit },
      findings,
      iocs,
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── DELETE /api/log-analysis/uploads/[id] ──────────────────────────────────
export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  const orgActor = await actorOr401(req);
  if (orgActor instanceof NextResponse) return orgActor;
  const orgDenied = await guardOrgAccess(orgActor, { logUploadId: params.id });
  if (orgDenied) return orgDenied;
  try {
    await requireAuth(req);
    const locked = await guardDeletion({ logUploadId: params.id }, "deleting this upload");
    if (locked) return locked;
    await prisma.logUpload.delete({ where: { id: params.id } });
    return NextResponse.json({ ok: true });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
