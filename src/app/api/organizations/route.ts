export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isAppliance } from "@/lib/config/deployment";
import { z } from "zod";

const createSchema = z.object({
  name: z.string().min(1).max(100),
  slug: z.string().min(1).max(50).regex(/^[a-z0-9-]+$/),
  description: z.string().optional(),
  plan: z.enum(["free", "enterprise"]).optional(),
});

export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  // platform_admin sees all; org_admin/others see only their orgs
  const where =
    actor.role === "platform_admin"
      ? {}
      : { members: { some: { userId: actor.id } } };

  const orgs = await prisma.organization.findMany({
    where,
    include: {
      _count: { select: { members: true, investigations: true, cases: true } },
    },
    orderBy: { createdAt: "desc" },
  });
  return NextResponse.json({ organizations: orgs });
}

export async function POST(req: NextRequest) {
  // Forensicator Core always runs in appliance mode — single org, seeded at
  // setup — so this always 403s in practice. Kept (rather than removed
  // outright) so this file stays a minimal diff against the Enterprise
  // overlay's version, for its SaaS multi-org mode.
  if (isAppliance()) {
    return NextResponse.json(
      { error: "Organization creation is disabled — this deployment is scoped to a single organization" },
      { status: 403 }
    );
  }

  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (actor.role !== "platform_admin") {
    return NextResponse.json(
      { error: "Forbidden — only platform administrators may create organizations" },
      { status: 403 }
    );
  }

  const body = createSchema.parse(await req.json());

  const existing = await prisma.organization.findUnique({ where: { slug: body.slug } });
  if (existing) return NextResponse.json({ error: "Slug already taken" }, { status: 409 });

  const org = await prisma.organization.create({
    data: {
      ...body,
      members: {
        create: { userId: actor.id, role: "org_admin", joinedAt: new Date() },
      },
    },
    include: { _count: { select: { members: true } } },
  });

  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "org_created", resourceType: "organization", resourceId: org.id,
      organizationId: org.id, severity: "info",
    },
  });

  return NextResponse.json({ organization: org }, { status: 201 });
}
