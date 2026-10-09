export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

type Params = { params: Promise<{ id: string }> };

/**
 * GET /api/investigations/[id]/graph
 * Returns { categories, meta } for the collapsible Evidence Graph.
 * Only returns host + category nodes — findings are loaded lazily per category.
 */
export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const inv = await prisma.investigation.findFirst({
    where: { id: params.id, ...orgWhere(actor) },
    select: { id: true, hostname: true },
  });
  if (!inv) return NextResponse.json({ error: "Not found" }, { status: 404 });

  // Aggregate finding counts per category
  const groups = await prisma.finding.groupBy({
    by: ["category"],
    where: { investigationId: params.id },
    _count: { id: true },
    orderBy: { _count: { id: "desc" } },
  });

  const totalFindings = groups.reduce((acc, g) => acc + g._count.id, 0);

  const categories = groups.map((g) => ({
    id: `cat-${params.id}-${g.category}`,
    label: g.category,
    count: g._count.id,
  }));

  return NextResponse.json({
    categories,
    meta: {
      hostname: inv.hostname ?? inv.id,
      categoryCount: categories.length,
      findingCount: totalFindings,
    },
  });
}
