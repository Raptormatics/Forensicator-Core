export const runtime = "nodejs";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";

type Params = { params: Promise<{ id: string }> };

export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  const actor = await getUploadActor(req);
  // Only the caller's own keys — this used to revoke any key by id.
  const revoked = await prisma.apiKey.updateMany({ where: { id: params.id, userId: actor.id }, data: { active: false } });
  if (revoked.count === 0) return NextResponse.json({ error: "Not found" }, { status: 404 });
  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "api_key_revoked", resourceType: "api_key", resourceId: params.id,
      severity: "warning",
    },
  });
  return NextResponse.json({ revoked: true });
}
