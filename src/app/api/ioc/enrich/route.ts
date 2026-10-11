/**
 * POST /api/ioc/enrich
 * Looks up or creates an IocRecord and queues enrichment if not already done recently.
 */
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getEnrichmentQueue } from "@/lib/jobs/queues";
import { getUploadActor } from "@/lib/upload/actor";

export const runtime = "nodejs";

const bodySchema = z.object({
  value: z.string().min(1).max(2048),
  type: z.enum(["ip", "hash", "url", "domain", "email"]),
  force: z.boolean().optional().default(false),
});

export async function POST(request: NextRequest) {
  try {
    const body = bodySchema.parse(await request.json());
    const actor = await getUploadActor(request);

    // Re-enrichment cooldown: 6 hours unless force=true
    const staleBefore = new Date(Date.now() - 6 * 60 * 60 * 1000);

    let record = await prisma.iocRecord.findUnique({ where: { value: body.value } });

    if (!record) {
      record = await prisma.iocRecord.create({
        data: { value: body.value, type: body.type },
      });
    }

    const isStale = !record.enrichedAt || record.enrichedAt < staleBefore;

    if (!isStale && !body.force) {
      return NextResponse.json({
        iocRecord: { id: record.id, value: record.value, type: record.type },
        queued: false,
        reason: "recently_enriched",
      });
    }

    const queue = getEnrichmentQueue();
    const job = await queue.add("enrich", {
      iocRecordId: record.id,
      value: body.value,
      type: body.type,
      organizationId: actor.organizationIds[0],
    });

    await prisma.iocRecord.update({
      where: { id: record.id },
      data: { enrichJobId: job.id ?? null },
    });

    await prisma.activityLog.create({
      data: {
        userId: actor.id,
        action: "ioc_enriched",
        entityType: "ioc",
        entityId: record.id,
        metadata: { value: body.value, type: body.type } as never,
      },
    });

    return NextResponse.json({
      iocRecord: { id: record.id, value: record.value, type: record.type },
      queued: true,
      jobId: job.id,
    }, { status: 202 });
  } catch (err) {
    if (err instanceof z.ZodError) return NextResponse.json({ error: "invalid_params", issues: err.flatten() }, { status: 400 });
    console.error("[ioc/enrich]", err);
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
