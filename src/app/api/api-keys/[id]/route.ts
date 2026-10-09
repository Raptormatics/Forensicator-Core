export const runtime = "nodejs";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";

type Params = { params: { id: string } };

export async function DELETE(req: NextRequest, { params }: Params) {
  const actor = await getUploadActor(req);
  await prisma.apiKey.update({ where: { id: params.id }, data: { active: false } });
  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "api_key_revoked", resourceType: "api_key", resourceId: params.id,
      severity: "warning",
    },
  });
  return NextResponse.json({ revoked: true });
}
