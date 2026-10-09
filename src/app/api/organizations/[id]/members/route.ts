export const runtime = "nodejs";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";
import { z } from "zod";

type Params = { params: Promise<{ id: string }> };

const addSchema = z.object({
  userId: z.string().uuid().optional(),
  email: z.string().email().optional(),
  role: z.enum(["org_admin", "analyst", "read_only", "auditor"]).default("analyst"),
});

// GET /api/organizations/[id]/members
export async function GET(_req: NextRequest, props: Params) {
  const params = await props.params;
  const members = await prisma.organizationMember.findMany({
    where: { organizationId: params.id },
    include: { user: { select: { id: true, email: true, name: true, role: true, createdAt: true } } },
    orderBy: { createdAt: "asc" },
  });
  return NextResponse.json({ members });
}

// POST /api/organizations/[id]/members — add member
export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  const actor = await getUploadActor(req);
  const body = addSchema.parse(await req.json());

  let userId = body.userId;
  if (!userId && body.email) {
    const user = await prisma.user.findUnique({ where: { email: body.email } });
    if (!user) return NextResponse.json({ error: "User not found" }, { status: 404 });
    userId = user.id;
  }
  if (!userId) return NextResponse.json({ error: "userId or email required" }, { status: 400 });

  const member = await prisma.organizationMember.upsert({
    where: { organizationId_userId: { organizationId: params.id, userId } },
    update: { role: body.role, active: true },
    create: { organizationId: params.id, userId, role: body.role, joinedAt: new Date() },
    include: { user: { select: { id: true, email: true, name: true } } },
  });

  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "member_added", resourceType: "organization_member", resourceId: member.id,
      organizationId: params.id, metadata: { role: body.role } as never, severity: "info",
    },
  });

  return NextResponse.json({ member }, { status: 201 });
}

// DELETE /api/organizations/[id]/members — remove member
export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  const actor = await getUploadActor(req);
  const { userId } = await req.json();
  await prisma.organizationMember.deleteMany({
    where: { organizationId: params.id, userId },
  });
  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "member_removed", resourceType: "organization_member", resourceId: userId,
      organizationId: params.id, severity: "warning",
    },
  });
  return NextResponse.json({ removed: true });
}
