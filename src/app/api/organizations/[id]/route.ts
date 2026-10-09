export const runtime = "nodejs";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { z } from "zod";

type Params = { params: Promise<{ id: string }> };

const patchSchema = z.object({
  name:        z.string().min(1).max(100).optional(),
  description: z.string().nullable().optional(),
  website:     z.string().url().nullable().optional(),
  logoUrl:     z.string().url().nullable().optional(),
  plan:        z.enum(["free", "professional", "enterprise"]).optional(),
  settings:    z.record(z.unknown()).optional(),
  maxUsers:    z.number().int().optional(),
  maxInvestigations: z.number().int().optional(),
  maxStorageGb: z.number().int().optional(),
});

export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  // Ensure actor can access this org
  if (actor.role !== "platform_admin" && !actor.organizationIds.includes(params.id)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const org = await prisma.organization.findUnique({
    where: { id: params.id },
    include: {
      members: { include: { user: { select: { id: true, email: true, name: true, role: true } } } },
      _count: { select: { investigations: true, cases: true, hostProfiles: true } },
    },
  });
  if (!org) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ organization: org });
}

export async function PATCH(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  // org_admin may only edit their own org; platform_admin can edit any
  if (actor.role !== "platform_admin" && !actor.organizationIds.includes(params.id)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const body = patchSchema.parse(await req.json());

  // org_admin cannot change plan
  if (actor.role !== "platform_admin") {
    delete (body as Record<string, unknown>).plan;
    delete (body as Record<string, unknown>).maxUsers;
    delete (body as Record<string, unknown>).maxInvestigations;
    delete (body as Record<string, unknown>).maxStorageGb;
  }

  const org = await prisma.organization.update({
    where: { id: params.id },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    data: body as any,
  });
  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "org_updated", resourceType: "organization", resourceId: params.id,
      organizationId: params.id, metadata: body as never, severity: "info",
    },
  });
  return NextResponse.json({ organization: org });
}

export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (actor.role !== "platform_admin") {
    return NextResponse.json({ error: "Forbidden — only platform administrators may delete organizations." }, { status: 403 });
  }

  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "org_deleted", resourceType: "organization", resourceId: params.id,
      severity: "critical",
    },
  });
  await prisma.organization.delete({ where: { id: params.id } });
  return NextResponse.json({ deleted: true });
}
