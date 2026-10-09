/**
 * PATCH /api/findings/[id]/status — update a finding's workflow status.
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";

export const runtime = "nodejs";

const VALID_STATUSES = ["new", "under_review", "confirmed", "false_positive", "escalated", "resolved"] as const;

const bodySchema = z.object({
  status: z.enum(VALID_STATUSES),
});

export async function PATCH(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const { status } = bodySchema.parse(await request.json());
    const actor = await getUploadActor(request);

    const finding = await prisma.finding.findUnique({
      where: { id: params.id },
      select: { id: true, workflowStatus: true, investigationId: true },
    });
    if (!finding) return NextResponse.json({ error: "not_found" }, { status: 404 });

    const updated = await prisma.finding.update({
      where: { id: params.id },
      data: { workflowStatus: status },
      select: { id: true, workflowStatus: true },
    });

    await prisma.activityLog.create({
      data: {
        userId: actor.id,
        action: "status_change",
        entityType: "finding",
        entityId: params.id,
        investigationId: finding.investigationId,
        metadata: { from: finding.workflowStatus, to: status } as never,
      },
    });

    return NextResponse.json({ finding: updated });
  } catch (err) {
    if (err instanceof z.ZodError) return NextResponse.json({ error: "invalid_params", issues: err.flatten() }, { status: 400 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
