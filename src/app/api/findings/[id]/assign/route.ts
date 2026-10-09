/**
 * POST /api/findings/[id]/assign — assign a finding to an analyst.
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";

export const runtime = "nodejs";

const bodySchema = z.object({
  assigneeId: z.string().uuid().nullable(),
});

export async function POST(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const { assigneeId } = bodySchema.parse(await request.json());
    const actor = await getUploadActor(request);

    const finding = await prisma.finding.findUnique({
      where: { id: params.id },
      select: { id: true, investigationId: true, assigneeId: true },
    });
    if (!finding) return NextResponse.json({ error: "not_found" }, { status: 404 });

    const updated = await prisma.finding.update({
      where: { id: params.id },
      data: { assigneeId },
      select: { id: true, assigneeId: true },
    });

    await prisma.activityLog.create({
      data: {
        userId: actor.id,
        action: "assignment",
        entityType: "finding",
        entityId: params.id,
        investigationId: finding.investigationId,
        metadata: { assigneeId } as never,
      },
    });

    return NextResponse.json({ finding: updated });
  } catch (err) {
    if (err instanceof z.ZodError) return NextResponse.json({ error: "invalid_params", issues: err.flatten() }, { status: 400 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
