export const runtime = "nodejs";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { randomBytes, createHash } from "crypto";

const schema = z.object({ email: z.string().email() });

export async function POST(req: NextRequest) {
  try {
    const { email } = schema.parse(await req.json());

    const user = await prisma.user.findUnique({ where: { email } });
    // Always return 200 to prevent email enumeration
    if (!user || !user.isActive) {
      return NextResponse.json({ ok: true });
    }

    // Invalidate old tokens
    await prisma.passwordResetToken.deleteMany({ where: { email } });

    const token     = randomBytes(32).toString("hex");
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await prisma.passwordResetToken.create({
      data: { email, tokenHash, expiresAt },
    });

    // In production: send email with token link
    // For now: log to console (replace with your email provider)
    const resetUrl = `${process.env.NEXTAUTH_URL}/reset-password?token=${token}`;
    console.log(`[PASSWORD RESET] ${email} → ${resetUrl}`);

    await prisma.auditLog.create({
      data: {
        actorEmail: email,
        action: "password_reset_requested",
        resourceType: "user",
        resourceId: user.id,
        severity: "info",
      },
    });

    return NextResponse.json({ ok: true });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return NextResponse.json({ error: "Invalid email" }, { status: 400 });
    }
    console.error("[forgot-password]", err);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
