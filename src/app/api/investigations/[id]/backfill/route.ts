/**
 * POST /api/investigations/[id]/backfill
 *
 * Re-extracts Evidence + TimelineEvent rows from the already-stored Finding
 * JSON for the given investigation.  Safe to call multiple times — it deletes
 * any previously extracted rows first so there are no duplicates.
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { extractEvidence, extractTimelineEvents } from "@/lib/upload/evidence-extractor";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import type { FindingJson } from "@/types/findings";
import type { JsonObject } from "@/types/json";

export const runtime = "nodejs";

export async function POST(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(request); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const investigationId = params.id;

  const investigation = await prisma.investigation.findFirst({
    where: { id: investigationId, ...orgWhere(actor) },
    select: { id: true, title: true },
  });

  if (!investigation) {
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  }

  // Load all findings with their stored JSON + sourceCategory.
  const findings = await prisma.finding.findMany({
    where: { investigationId },
    select: { id: true, sourceCategory: true, data: true },
  });

  // Delete previously extracted rows so the backfill is idempotent.
  await prisma.timelineEvent.deleteMany({ where: { investigationId } });
  await prisma.evidence.deleteMany({ where: { investigationId } });

  const evidenceRows = [];
  const timelineRows = [];

  for (const finding of findings) {
    const data = finding.data as unknown as FindingJson;
    if (!Array.isArray(data.evidence) || data.evidence.length === 0) continue;

    evidenceRows.push(
      ...extractEvidence(
        data,
        investigationId,
        finding.id,
        finding.sourceCategory
      )
    );
    timelineRows.push(
      ...extractTimelineEvents(data, investigationId, finding.id)
    );
  }

  const EV_BATCH = 500;
  for (let i = 0; i < evidenceRows.length; i += EV_BATCH) {
    await prisma.evidence.createMany({ data: evidenceRows.slice(i, i + EV_BATCH) });
  }

  const TL_BATCH = 500;
  for (let i = 0; i < timelineRows.length; i += TL_BATCH) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await prisma.timelineEvent.createMany({ data: timelineRows.slice(i, i + TL_BATCH) as any[] });
  }

  return NextResponse.json({
    investigation: { id: investigation.id, title: investigation.title },
    findings_processed: findings.length,
    evidence_rows: evidenceRows.length,
    timeline_events: timelineRows.length,
  });
}
