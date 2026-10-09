/**
 * POST /api/reports/generate
 * Enqueues a report generation job.
 */
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getReportQueue } from "@/lib/jobs/queues";
import { getUploadActor } from "@/lib/upload/actor";

export const runtime = "nodejs";

const bodySchema = z.object({
  caseId: z.string().uuid(),
  type:   z.enum(["executive", "technical"]),
  format: z.enum(["pdf", "csv", "json", "zip"]),
});

export async function POST(request: NextRequest) {
  try {
    const body = bodySchema.parse(await request.json());
    const actor = await getUploadActor(request);

    const kase = await prisma.case.findUnique({ where: { id: body.caseId }, select: { id: true } });
    if (!kase) return NextResponse.json({ error: "not_found" }, { status: 404 });

    const report = await prisma.report.create({
      data: {
        caseId: body.caseId,
        generatedById: actor.id,
        type: body.type,
        format: body.format,
        status: "queued",
      },
    });

    const queue = getReportQueue();
    const job = await queue.add("generate", {
      reportId: report.id,
      caseId: body.caseId,
      type: body.type,
      format: body.format,
      requestedById: actor.id,
    });

    await prisma.report.update({ where: { id: report.id }, data: { jobId: job.id } });

    await prisma.activityLog.create({
      data: {
        userId: actor.id,
        action: "report_generated",
        entityType: "report",
        entityId: report.id,
        metadata: { caseId: body.caseId, type: body.type, format: body.format } as never,
      },
    });

    return NextResponse.json({ report: { id: report.id, status: "queued", type: body.type, format: body.format } }, { status: 202 });
  } catch (err) {
    if (err instanceof z.ZodError) return NextResponse.json({ error: "invalid_params", issues: err.flatten() }, { status: 400 });
    const message = err instanceof Error ? err.message : String(err);
    console.error("[reports/generate]", message);
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}
