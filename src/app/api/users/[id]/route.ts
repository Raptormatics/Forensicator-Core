export const runtime = "nodejs";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, type AuthActor } from "@/lib/auth/api-guard";
import { z } from "zod";

const ADMIN_ROLES = ["platform_admin", "org_admin"];

function inActorOrg(actor: AuthActor, target: { orgMemberships: { organizationId: string }[] }): boolean {
  return target.orgMemberships.some((m) => actor.organizationIds.includes(m.organizationId));
}

const patchSchema = z.object({
  name:      z.string().min(1).max(100).optional(),
  firstName: z.string().max(50).optional(),
  lastName:  z.string().max(50).optional(),
  role:      z.enum(["platform_admin", "org_admin", "analyst", "read_only", "auditor"]).optional(),
  isActive:  z.boolean().optional(),
});

// GET /api/users/[id]
export async function GET(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    await getActorOrThrow(req);
  } catch (e) {
    if (e instanceof AuthError) return e.toResponse();
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }

  const user = await prisma.user.findUnique({
    where: { id: params.id },
    select: {
      id: true, email: true, name: true, firstName: true, lastName: true,
      role: true, isActive: true, lastLogin: true, createdAt: true,
      orgMemberships: { select: { role: true, organization: { select: { id: true, name: true } } } },
      _count: { select: { investigations: true, createdCases: true, apiKeys: true } },
    },
  });

  if (!user) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ user });
}

// PATCH /api/users/[id] — update role, activate/deactivate, name
export async function PATCH(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  let actor;
  try {
    actor = await getActorOrThrow(req);
  } catch (e) {
    if (e instanceof AuthError) return e.toResponse();
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }

  if (!ADMIN_ROLES.includes(actor.role)) {
    return NextResponse.json({ error: "Forbidden — admin role required" }, { status: 403 });
  }

  // Prevent demoting/deactivating yourself
  if (params.id === actor.id) {
    return NextResponse.json({ error: "You cannot modify your own account from this endpoint." }, { status: 400 });
  }

  try {
    const body = patchSchema.parse(await req.json());

    const target = await prisma.user.findUnique({
      where: { id: params.id },
      include: { orgMemberships: { select: { organizationId: true } } },
    });
    if (!target) return NextResponse.json({ error: "User not found" }, { status: 404 });

    // org_admin may only manage users within their own org(s), and never
    // platform_admins — either as a target or as a role to grant.
    if (actor.role === "org_admin" && !inActorOrg(actor, target)) {
      return NextResponse.json({ error: "Forbidden — user is not in your organization." }, { status: 403 });
    }
    if (actor.role === "org_admin" && target.role === "platform_admin") {
      return NextResponse.json({ error: "Forbidden — cannot modify platform admins" }, { status: 403 });
    }
    if (actor.role === "org_admin" && body.role === "platform_admin") {
      return NextResponse.json(
        { error: "Forbidden — org_admin cannot grant platform_admin." },
        { status: 403 }
      );
    }

    const updated = await prisma.user.update({
      where: { id: params.id },
      data:  body,
      select: { id: true, email: true, name: true, role: true, isActive: true, updatedAt: true },
    });

    await prisma.auditLog.create({
      data: {
        actorId: actor.id, actorEmail: actor.email,
        action: body.isActive !== undefined
          ? (body.isActive ? "user_activated" : "user_deactivated")
          : "user_updated",
        resourceType: "user", resourceId: params.id,
        organizationId: target.orgMemberships[0]?.organizationId ?? null,
        metadata: body as object,
        severity: "warning",
      },
    });

    return NextResponse.json({ user: updated });
  } catch (e) {
    if (e instanceof z.ZodError) return NextResponse.json({ error: e.errors[0].message }, { status: 400 });
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}

// DELETE /api/users/[id] — permanently deletes the user. platform_admin may
// delete anyone; org_admin may delete non-platform_admin users within their
// own org(s).
export async function DELETE(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  let actor;
  try {
    actor = await getActorOrThrow(req);
  } catch (e) {
    if (e instanceof AuthError) return e.toResponse();
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }

  if (!ADMIN_ROLES.includes(actor.role)) {
    return NextResponse.json({ error: "Forbidden — admin role required" }, { status: 403 });
  }

  if (params.id === actor.id) {
    return NextResponse.json({ error: "You cannot delete your own account." }, { status: 400 });
  }

  const target = await prisma.user.findUnique({
    where: { id: params.id },
    include: { orgMemberships: { select: { organizationId: true } } },
  });
  if (!target) return NextResponse.json({ error: "Not found" }, { status: 404 });

  if (actor.role === "org_admin") {
    if (!inActorOrg(actor, target)) {
      return NextResponse.json({ error: "Forbidden — user is not in your organization." }, { status: 403 });
    }
    if (target.role === "platform_admin") {
      return NextResponse.json({ error: "Forbidden — cannot delete platform admins" }, { status: 403 });
    }
  }

  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "user_deleted", resourceType: "user", resourceId: params.id,
      organizationId: target.orgMemberships[0]?.organizationId ?? null,
      metadata: { email: target.email, role: target.role } as object,
      severity: "critical",
    },
  });

  await prisma.user.delete({ where: { id: params.id } });

  return NextResponse.json({ deleted: true });
}
