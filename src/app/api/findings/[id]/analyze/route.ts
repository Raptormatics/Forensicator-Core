/**
 * POST /api/findings/[id]/analyze — analyst-triggered Forensicator AI
 * analysis for a single finding. Enqueues rather than running inline
 * (mirrors /api/ioc/enrich): local CPU inference is slow enough per
 * finding that auto-triggering it across every finding in every upload
 * would be a significant, surprising background load — this only runs
 * when an analyst asks for it.
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";
import { getAiQueue } from "@/lib/jobs/queues";

export const runtime = "nodejs";

const bodySchema = z.object({
  force: z.boolean().optional().default(false),
});

export async function POST(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const { force } = bodySchema.parse(await request.json().catch(() => ({})));
    const actor = await getUploadActor(request);

    const finding = await prisma.finding.findUnique({
      where: { id: params.id },
      select: { id: true, investigationId: true, aiStatus: true },
    });
    if (!finding) return NextResponse.json({ error: "not_found" }, { status: 404 });

    if (finding.aiStatus === "processing" && !force) {
      return NextResponse.json({ queued: false, reason: "already_processing", aiStatus: finding.aiStatus });
    }
    if (finding.aiStatus === "complete" && !force) {
      return NextResponse.json({ queued: false, reason: "already_analyzed", aiStatus: finding.aiStatus });
    }

    await prisma.finding.update({ where: { id: params.id }, data: { aiStatus: "pending" } });

    const queue = getAiQueue();
    const job = await queue.add("analyze", { findingId: params.id });

    await prisma.activityLog.create({
      data: {
        userId: actor.id,
        action: "ai_analysis_requested",
        entityType: "finding",
        entityId: params.id,
        investigationId: finding.investigationId,
        metadata: { force } as never,
      },
    });

    return NextResponse.json({ queued: true, jobId: job.id, aiStatus: "pending" }, { status: 202 });
  } catch (err) {
    if (err instanceof z.ZodError) return NextResponse.json({ error: "invalid_params", issues: err.flatten() }, { status: 400 });
    console.error("[findings/analyze]", err);
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// GET — lightweight status poll for the finding-detail panel while a job runs.
export async function GET(_request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  const finding = await prisma.finding.findUnique({
    where: { id: params.id },
    select: { aiStatus: true, aiSummary: true, aiConfidence: true, aiModel: true, aiEnrichedAt: true, data: true },
  });
  if (!finding) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const data = finding.data as { ai_analysis?: Record<string, unknown> } | null;
  return NextResponse.json({
    aiStatus: finding.aiStatus,
    aiSummary: finding.aiSummary,
    aiConfidence: finding.aiConfidence,
    aiModel: finding.aiModel,
    aiEnrichedAt: finding.aiEnrichedAt,
    aiAnalysis: data?.ai_analysis ?? null,
  });
}
