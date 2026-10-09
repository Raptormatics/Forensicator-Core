export const runtime = "nodejs";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getActorOrThrow } from "@/lib/auth/api-guard";
import { prisma } from "@/lib/db/prisma";
import bcrypt from "bcryptjs";

const updateProfileSchema = z.object({
  name:      z.string().min(1).max(100).optional(),
  firstName: z.string().max(50).optional(),
  lastName:  z.string().max(50).optional(),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword:     z.string().min(8).max(128),
});

// GET /api/auth/profile
export async function GET(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    const user  = await prisma.user.findUnique({
      where:  { id: actor.id },
      select: {
        id: true, email: true, name: true,
        firstName: true, lastName: true,
        role: true, isActive: true, lastLogin: true,
        createdAt: true,
        _count: { select: { apiKeys: true } },
      },
    });
    if (!user) return NextResponse.json({ error: "Not found" }, { status: 404 });
    return NextResponse.json({ user });
  } catch (e) {
    if (e instanceof NextResponse) return e;
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}

// PATCH /api/auth/profile
export async function PATCH(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    const body  = await req.json();

    // Check which operation
    if ("newPassword" in body) {
      // Change password
      const { currentPassword, newPassword } = changePasswordSchema.parse(body);
      const user = await prisma.user.findUnique({ where: { id: actor.id } });
      if (!user?.passwordHash) {
        return NextResponse.json({ error: "No password set on this account." }, { status: 400 });
      }
      const valid = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!valid) {
        return NextResponse.json({ error: "Current password is incorrect." }, { status: 400 });
      }
      const passwordHash = await bcrypt.hash(newPassword, 12);
      await prisma.user.update({ where: { id: actor.id }, data: { passwordHash } });
      await prisma.auditLog.create({
        data: {
          actorId: actor.id, actorEmail: actor.email,
          action: "password_changed", resourceType: "user", resourceId: actor.id, severity: "info",
        },
      });
      return NextResponse.json({ ok: true });
    }

    // Update profile fields
    const data = updateProfileSchema.parse(body);
    const updated = await prisma.user.update({
      where:  { id: actor.id },
      data,
      select: { id: true, email: true, name: true, firstName: true, lastName: true, role: true },
    });
    return NextResponse.json({ user: updated });
  } catch (e) {
    if (e instanceof NextResponse) return e;
    if (e instanceof z.ZodError) return NextResponse.json({ error: "Invalid input" }, { status: 400 });
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
