export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { z } from "zod";

const ADMIN_ROLES = ["platform_admin", "org_admin"];

export async function GET(req: NextRequest) {
  let actor;
  try {
    actor = await getActorOrThrow(req);
  } catch (e) {
    if (e instanceof AuthError) return e.toResponse();
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }

  const { searchParams } = new URL(req.url);
  const q     = searchParams.get("q") ?? undefined;
  const orgId = searchParams.get("organizationId") ?? undefined;
  const page  = Math.max(1, Number(searchParams.get("page") ?? 1));
  const limit = Math.min(100, Number(searchParams.get("limit") ?? 50));

  // Org-admin and below can only see users within their orgs
  const orgScope: string[] | undefined =
    actor.role === "platform_admin"
      ? undefined                    // no restriction
      : actor.organizationIds;       // only their orgs

  const where = {
    ...(q ? {
      OR: [
        { email: { contains: q, mode: "insensitive" as const } },
        { name:  { contains: q, mode: "insensitive" as const } },
      ],
    } : {}),
    // Explicit orgId filter (from query param) — intersect with scope
    ...(orgId
      ? { orgMemberships: { some: { organizationId: orgId } } }
      : orgScope !== undefined
        ? { orgMemberships: { some: { organizationId: { in: orgScope } } } }
        : {}),
  };

  const [total, users] = await Promise.all([
    prisma.user.count({ where }),
    prisma.user.findMany({
      where,
      skip: (page - 1) * limit,
      take: limit,
      orderBy: { createdAt: "desc" },
      select: {
        id: true, email: true, name: true, role: true,
        isActive: true, lastLogin: true, createdAt: true,
        orgMemberships: { select: { role: true, organization: { select: { id: true, name: true } } } },
        _count: { select: { investigations: true, createdCases: true } },
      },
    }),
  ]);

  return NextResponse.json({ users, total, page, limit, pages: Math.ceil(total / limit) });
}

const createSchema = z.object({
  email:     z.string().email(),
  name:      z.string().min(1).max(100).optional(),
  firstName: z.string().max(50).optional(),
  lastName:  z.string().max(50).optional(),
  role:      z.enum(["platform_admin", "org_admin", "analyst", "read_only", "auditor"]).default("analyst"),
  password:  z.string().min(8).max(128),
  organizationId: z.string().uuid().optional(),
});

export async function POST(req: NextRequest) {
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

  try {
    const body = createSchema.parse(await req.json());

    // Roles that must belong to an organization
    const ORG_REQUIRED_ROLES = ["org_admin", "analyst", "read_only"];

    // org_admin cannot create platform_admin users
    if (actor.role === "org_admin" && body.role === "platform_admin") {
      return NextResponse.json(
        { error: "Forbidden — org_admin cannot create platform_admin users." },
        { status: 403 }
      );
    }

    // For org_admin actors: always assign to their own org (ignore or override any supplied orgId)
    let resolvedOrgId = body.organizationId;
    if (actor.role === "org_admin") {
      resolvedOrgId = actor.organizationIds[0];
      if (!resolvedOrgId) {
        return NextResponse.json(
          { error: "Your account is not associated with any organization." },
          { status: 403 }
        );
      }
    }

    if (ORG_REQUIRED_ROLES.includes(body.role) && !resolvedOrgId) {
      return NextResponse.json(
        { error: `An organization must be selected for the '${body.role}' role.` },
        { status: 400 }
      );
    }

    // platform_admin can only assign users to orgs they belong to (if supplied)
    if (actor.role === "platform_admin" && body.organizationId && !actor.organizationIds.includes(body.organizationId)) {
      // platform_admin can assign to any org — no restriction needed
    }

    const existing = await prisma.user.findUnique({ where: { email: body.email.toLowerCase() } });
    if (existing) return NextResponse.json({ error: "A user with this email already exists." }, { status: 409 });

    const passwordHash = await bcrypt.hash(body.password, 12);

    const user = await prisma.user.create({
      data: {
        email:     body.email.toLowerCase(),
        name:      body.name,
        firstName: body.firstName,
        lastName:  body.lastName,
        role:      body.role,
        passwordHash,
        isActive: true,
        ...(resolvedOrgId ? {
          orgMemberships: {
            create: { organizationId: resolvedOrgId, role: "member", joinedAt: new Date() },
          },
        } : {}),
      },
      select: { id: true, email: true, name: true, role: true, isActive: true, createdAt: true },
    });

    await prisma.auditLog.create({
      data: {
        actorId: actor.id, actorEmail: actor.email,
        action: "user_created", resourceType: "user", resourceId: user.id,
        organizationId: resolvedOrgId ?? null,
        severity: "info",
      },
    });

    return NextResponse.json({ user }, { status: 201 });
  } catch (e) {
    if (e instanceof z.ZodError) return NextResponse.json({ error: e.errors[0].message }, { status: 400 });
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
