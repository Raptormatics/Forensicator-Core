export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

type Params = { params: Promise<{ id: string }> };

/**
 * GET /api/cases/[id]/findings — searchable list of Finding rows across
 * every investigation linked to this case, for the Case Tasks
 * "related findings" picker (src/app/cases/[id]/page.tsx).
 */
export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const kase = await prisma.case.findFirst({ where: { id: params.id, ...orgWhere(actor) } });
  if (!kase) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const caseInvs = await prisma.investigation.findMany({
    where: { caseId: params.id },
    select: { id: true },
  });
  const investigationIds = caseInvs.map((ci) => ci.id);
  if (investigationIds.length === 0) return NextResponse.json({ findings: [] });

  const { searchParams } = new URL(req.url);
  const q = searchParams.get("q")?.trim();
  const idsParam = searchParams.get("ids")?.trim();

  // Resolve specific finding ids (e.g. to render already-linked chips) —
  // bypasses search matching entirely when present.
  if (idsParam) {
    const ids = idsParam.split(",").filter(Boolean);
    const findings = ids.length > 0
      ? await prisma.finding.findMany({
          where: { id: { in: ids }, investigationId: { in: investigationIds } },
          select: {
            id: true, findingId: true, findingType: true, category: true, severity: true,
            investigation: { select: { id: true, hostname: true } },
          },
        })
      : [];
    return NextResponse.json({ findings });
  }

  const findings = await prisma.finding.findMany({
    where: {
      investigationId: { in: investigationIds },
      ...(q ? { OR: [
        { findingType: { contains: q, mode: "insensitive" as const } },
        { category:    { contains: q, mode: "insensitive" as const } },
        { findingId:   { contains: q, mode: "insensitive" as const } },
      ] } : {}),
    },
    select: {
      id: true, findingId: true, findingType: true, category: true, severity: true,
      investigation: { select: { id: true, hostname: true } },
    },
    orderBy: { createdAt: "desc" },
    take: 50,
  });

  return NextResponse.json({ findings });
}
