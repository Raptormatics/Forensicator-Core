export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { encryptSecret } from "@/lib/crypto/secret-box";

const SINGLETON_ID = "singleton";

// GET — any authenticated user. Mirrors /api/settings/ai: nothing here is
// sensitive except the SMTP password, which is never returned (only its
// last 4 chars, for display).
export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const settings = await prisma.systemSettings.findUnique({ where: { id: SINGLETON_ID } });
  return NextResponse.json({
    criticalFindingAlertsEnabled: settings?.criticalFindingAlertsEnabled ?? false,
    notificationEmail: settings?.notificationEmail ?? null,
    smtpHost: settings?.smtpHost ?? null,
    smtpPort: settings?.smtpPort ?? 587,
    smtpUser: settings?.smtpUser ?? null,
    smtpPasswordLast4: settings?.smtpPasswordLast4 ?? null,
    hasSmtpPassword: !!settings?.smtpPasswordEncrypted,
    smtpFromAddress: settings?.smtpFromAddress ?? null,
    smtpSecure: settings?.smtpSecure ?? false,
  });
}

const putSchema = z.object({
  criticalFindingAlertsEnabled: z.boolean().optional(),
  notificationEmail: z.string().email().max(300).or(z.literal("")).optional(),
  smtpHost: z.string().max(500).optional(),
  smtpPort: z.number().int().min(1).max(65535).optional(),
  smtpUser: z.string().max(300).optional(),
  // Empty string clears the stored password; omit the field to leave it unchanged.
  smtpPassword: z.string().max(500).optional(),
  smtpFromAddress: z.string().max(300).optional(),
  smtpSecure: z.boolean().optional(),
});

// PUT — unrestricted (Core's sole user).
export async function PUT(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  let body;
  try {
    body = putSchema.parse(await req.json());
  } catch (e) {
    if (e instanceof z.ZodError) return NextResponse.json({ error: e.errors[0].message }, { status: 400 });
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const data: Record<string, unknown> = {};
  if (body.criticalFindingAlertsEnabled !== undefined) data.criticalFindingAlertsEnabled = body.criticalFindingAlertsEnabled;
  if (body.notificationEmail !== undefined) data.notificationEmail = body.notificationEmail === "" ? null : body.notificationEmail;
  if (body.smtpHost !== undefined) data.smtpHost = body.smtpHost.trim() === "" ? null : body.smtpHost.trim();
  if (body.smtpPort !== undefined) data.smtpPort = body.smtpPort;
  if (body.smtpUser !== undefined) data.smtpUser = body.smtpUser.trim() === "" ? null : body.smtpUser.trim();
  if (body.smtpFromAddress !== undefined) data.smtpFromAddress = body.smtpFromAddress.trim() === "" ? null : body.smtpFromAddress.trim();
  if (body.smtpSecure !== undefined) data.smtpSecure = body.smtpSecure;
  if (body.smtpPassword !== undefined) {
    if (body.smtpPassword === "") {
      data.smtpPasswordEncrypted = null;
      data.smtpPasswordLast4 = null;
    } else {
      data.smtpPasswordEncrypted = encryptSecret(body.smtpPassword);
      data.smtpPasswordLast4 = body.smtpPassword.slice(-4);
    }
  }

  const settings = await prisma.systemSettings.upsert({
    where: { id: SINGLETON_ID },
    update: data,
    create: { id: SINGLETON_ID, ...data },
  });

  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "notification_settings_updated",
      resourceType: "system_settings", resourceId: SINGLETON_ID,
      metadata: { ...data, smtpPasswordEncrypted: data.smtpPasswordEncrypted ? "[redacted]" : undefined } as object,
      severity: "warning",
    },
  });

  return NextResponse.json({
    criticalFindingAlertsEnabled: settings.criticalFindingAlertsEnabled,
    notificationEmail: settings.notificationEmail,
    smtpHost: settings.smtpHost,
    smtpPort: settings.smtpPort ?? 587,
    smtpUser: settings.smtpUser,
    smtpPasswordLast4: settings.smtpPasswordLast4,
    hasSmtpPassword: !!settings.smtpPasswordEncrypted,
    smtpFromAddress: settings.smtpFromAddress,
    smtpSecure: settings.smtpSecure,
  });
}
