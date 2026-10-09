/**
 * PATCH /api/findings/[id]/severity — manual analyst override of a finding's
 * severity (e.g. escalating an "Informational" finding that's actually part
 * of a confirmed malware investigation).
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";
import { SEVERITY_LABELS } from "@/lib/severity";

export const runtime = "nodejs";

const bodySchema = z.object({
  severity: z.enum(SEVERITY_LABELS as [string, ...string[]]),
});

export async function PATCH(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const { severity } = bodySchema.parse(await request.json());
    const actor = await getUploadActor(request);

    const finding = await prisma.finding.findUnique({
      where: { id: params.id },
      select: { id: true, severity: true, investigationId: true },
    });
    if (!finding) return NextResponse.json({ error: "not_found" }, { status: 404 });

    const updated = await prisma.finding.update({
      where: { id: params.id },
      data: { severity },
      select: { id: true, severity: true },
    });

    await prisma.activityLog.create({
      data: {
        userId: actor.id,
        action: "severity_change",
        entityType: "finding",
        entityId: params.id,
        investigationId: finding.investigationId,
        metadata: { from: finding.severity, to: severity } as never,
      },
    });

    return NextResponse.json({ finding: updated });
  } catch (err) {
    if (err instanceof z.ZodError) return NextResponse.json({ error: "invalid_params", issues: err.flatten() }, { status: 400 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
