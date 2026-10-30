export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { correlateCases } from "@/lib/correlation/engine";
import { analysisSources } from "@/lib/correlation/sources";
import { guardCaseOpen } from "@/lib/cases/case-lock";

/**
 * POST /api/correlations/run
 * Body: { caseId: string } — analysts pick a case, not individual
 * investigations; every investigation, PCAP, RAM and log analysis
 * linked to that case is fetched automatically and correlated. Safe to call
 * repeatedly on the same case — see the engine's union-merge behavior.
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
  const locked = await guardCaseOpen({ caseId }, "re-running correlation");
  if (locked) return locked;

  const ready = { caseId, status: "ready" };
  const [investigations, pcaps, rams, logs] = await Promise.all([
    prisma.investigation.count({ where: { caseId } }),
    prisma.pcapUpload.count({ where: ready }),
    prisma.ramUpload.count({ where: ready }),
    prisma.logUpload.count({ where: ready }),
  ]);
  if (investigations + pcaps + rams + logs < 2) {
    return NextResponse.json({ error: "This case needs at least 2 investigations or PCAP/RAM/log analyses to run correlation" }, { status: 400 });
  }

  try {
    const result = await correlateCases([caseId], analysisSources);
    return NextResponse.json(result);
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "Correlation failed" }, { status: 400 });
  }
}
