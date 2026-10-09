/**
 * POST /api/sigma/sync
 * Backfills sigma findings for an investigation (or all) when sourceCategory
 * is missing from older uploads. Updates sourceCategory = 'sigma' on any
 * Finding whose findingType contains "sigma" or whose data.evidence rows
 * have rule_title / rule_level fields.
 *
 * Body: { investigationId?: string }  — omit to backfill all investigations.
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";

export async function POST(req: NextRequest) {
  let actor;
  try {
    actor = await getActorOrThrow(req);
  } catch (e) {
    if (e instanceof AuthError) return e.toResponse();
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }

  const body = await req.json().catch(() => ({})) as { investigationId?: string };
  const invFilter = body.investigationId ? { investigationId: body.investigationId } : {};

  // Find findings whose findingType indicates sigma but sourceCategory is not set.
  const findings = await prisma.finding.findMany({
    where: {
      ...invFilter,
      OR: [
        { findingType: { contains: "sigma",      mode: "insensitive" } },
        { findingType: { contains: "Sigma Rule", mode: "insensitive" } },
      ],
      sourceCategory: null,
    },
    select: { id: true, findingType: true, investigationId: true },
  });

  if (findings.length === 0) {
    return NextResponse.json({ updated: 0, message: "Nothing to backfill — all sigma findings already tagged." });
  }

  await prisma.finding.updateMany({
    where: { id: { in: findings.map((f) => f.id) } },
    data:  { sourceCategory: "sigma" },
  });

  return NextResponse.json({
    updated: findings.length,
    message: `Tagged ${findings.length} finding(s) as sourceCategory='sigma'.`,
    investigations: [...new Set(findings.map((f) => f.investigationId))],
  });
}
