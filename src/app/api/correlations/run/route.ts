export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { runCorrelation } from "@/lib/correlation/engine";

/**
 * POST /api/correlations/run
 * Body: { caseId: string } — analysts pick a case, not individual
 * investigations; every investigation linked to that case is fetched
 * automatically and correlated. Safe to call repeatedly on the same case —
 * see runCorrelation()'s union-merge behavior.
 */
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const body = await req.json().catch(() => ({}));
  const caseId: unknown = body.caseId;
  if (typeof caseId !== "string" || !caseId) {
    return NextResponse.json({ error: "caseId is required" }, { status: 400 });
  }

  const kase = await prisma.case.findFirst({ where: { id: caseId, ...orgWhere(actor) } });
  if (!kase) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const links = await prisma.investigation.findMany({
    where: { caseId },
    select: { id: true },
  });
  if (links.length < 2) {
    return NextResponse.json({ error: "This case needs at least 2 linked investigations to run correlation" }, { status: 400 });
  }

  try {
    const result = await runCorrelation(links.map((l) => l.id), caseId);
    return NextResponse.json(result);
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "Correlation failed" }, { status: 400 });
  }
}
