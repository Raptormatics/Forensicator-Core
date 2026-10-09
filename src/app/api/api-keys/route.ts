export const runtime = "nodejs";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";
import { z } from "zod";
import { randomBytes } from "crypto";
import bcrypt from "bcryptjs";

const createSchema = z.object({
  name: z.string().min(1).max(100),
  scopes: z.array(z.string()).default([]),
  expiresAt: z.string().datetime().optional(),
  organizationId: z.string().uuid().optional(),
});

export async function GET(req: NextRequest) {
  const actor = await getUploadActor(req);
  const { searchParams } = new URL(req.url);
  const orgId = searchParams.get("organizationId") ?? undefined;

  const keys = await prisma.apiKey.findMany({
    where: { userId: actor.id, ...(orgId ? { organizationId: orgId } : {}) },
    select: {
      id: true, name: true, keyPrefix: true, scopes: true,
      active: true, lastUsedAt: true, expiresAt: true,
      usageCount: true, createdAt: true,
    },
    orderBy: { createdAt: "desc" },
  });
  return NextResponse.json({ keys });
}

export async function POST(req: NextRequest) {
  const actor = await getUploadActor(req);
  const body  = createSchema.parse(await req.json());

  // Generate a secure random key — prefix must be 8 chars (matches api-guard lookup)
  const rawKey    = `fk_${randomBytes(32).toString("hex")}`;
  const keyHash   = await bcrypt.hash(rawKey, 10);   // bcrypt — validated in api-guard
  const keyPrefix = rawKey.slice(0, 8);

  const key = await prisma.apiKey.create({
    data: {
      name: body.name,
      keyHash,
      keyPrefix,
      scopes: body.scopes,
      userId: actor.id,
      organizationId: body.organizationId,
      expiresAt: body.expiresAt ? new Date(body.expiresAt) : undefined,
    },
  });

  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "api_key_created", resourceType: "api_key", resourceId: key.id,
      organizationId: body.organizationId, severity: "warning",
    },
  });

  // Return the raw key only once — never stored in plaintext
  return NextResponse.json({
    key: {
      id: key.id, name: key.name, keyPrefix, scopes: key.scopes,
      expiresAt: key.expiresAt, createdAt: key.createdAt,
    },
    rawKey, // shown ONCE to user
  }, { status: 201 });
}
