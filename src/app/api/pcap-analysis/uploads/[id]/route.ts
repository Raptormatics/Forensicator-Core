import { NextRequest, NextResponse } from "next/server";
import { prisma }      from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";

type Params = { params: Promise<{ id: string }> };

// ── GET /api/pcap-analysis/uploads/[id] ────────────────────────────────────
export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    await requireAuth(req);
    const { id } = params;

    const upload = await prisma.pcapUpload.findUnique({
      where: { id },
      include: {
        uploadedBy:   { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
        _count:       { select: { conversations: true, dnsQueries: true, findings: true, iocs: true } },
      },
    });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Paginated conversations
    const url   = new URL(req.url);
    const page  = parseInt(url.searchParams.get("page") ?? "1", 10);
    const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "100", 10), 500);
    const skip  = (page - 1) * limit;

    const [conversations, conversationTotal] = await Promise.all([
      prisma.pcapConversation.findMany({
        where: { uploadId: id },
        orderBy: [{ bytesAtoB: "desc" }],
        skip,
        take: limit,
      }),
      prisma.pcapConversation.count({ where: { uploadId: id } }),
    ]);

    const dnsQueries = await prisma.pcapDnsQuery.findMany({
      where: { uploadId: id },
      orderBy: [{ count: "desc" }],
      take: 500,
    });

    // `severity` is free-text (critical/high/medium/low/info), so DB orderBy
    // would sort alphabetically — rank explicitly in JS instead.
    const RULE_SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const findings = (await prisma.pcapFinding.findMany({
      where: { uploadId: id },
      orderBy: { matchCount: "desc" },
      include: { rule: { select: { id: true, name: true, tags: true } } },
    })).sort((a, b) =>
      (RULE_SEVERITY_RANK[b.severity] ?? -1) - (RULE_SEVERITY_RANK[a.severity] ?? -1) || b.matchCount - a.matchCount
    );

    const iocs = await prisma.pcapIoc.findMany({
      where: { uploadId: id },
      orderBy: [{ count: "desc" }],
      take: 500,
    });

    return NextResponse.json({
      upload: { ...upload, byteCount: upload.byteCount.toString() },
      conversations: {
        data: conversations.map((c) => ({ ...c, bytesAtoB: c.bytesAtoB.toString(), bytesBtoA: c.bytesBtoA.toString() })),
        total: conversationTotal, page, limit,
      },
      dnsQueries,
      findings,
      iocs,
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── DELETE /api/pcap-analysis/uploads/[id] ─────────────────────────────────
export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    await requireAuth(req);
    await prisma.pcapUpload.delete({ where: { id: params.id } });
    return NextResponse.json({ ok: true });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
