export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

// GET /api/reports/list — reports scoped to actor's org
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  const orgFilter = orgWhere(actor);

  const reports = await prisma.report.findMany({
    where:
      Object.keys(orgFilter).length > 0
        ? { OR: [{ investigation: orgFilter }, { case: orgFilter }] }
        : {},
    include: {
      investigation: { select: { id: true, hostname: true } },
      case:          { select: { id: true, title: true, caseSeq: true } },
      generatedBy:   { select: { email: true, name: true } },
    },
    orderBy: { createdAt: "desc" },
    take: 200,
  });
  return NextResponse.json({ reports });
}
