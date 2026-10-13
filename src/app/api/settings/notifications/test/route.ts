/**
 * POST /api/settings/notifications/test — sends a real test email through
 * the currently SAVED SMTP config (or an optional override in the request
 * body, so the Settings page can test before hitting Save) to the given
 * recipient, mirroring /api/settings/ai/test's override-or-saved pattern.
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { getSmtpConfig, sendMail } from "@/lib/notifications/mailer";

const bodySchema = z.object({
  to: z.string().email(),
  smtpHost: z.string().max(500).optional(),
  smtpPort: z.number().int().min(1).max(65535).optional(),
  smtpUser: z.string().max(300).optional(),
  // Blank means "use the saved password" — the Settings form never shows
  // the real password back, so it can't send it as an override unless the
  // admin just typed a new one.
  smtpPassword: z.string().max(500).optional(),
  smtpFromAddress: z.string().max(300).optional(),
  smtpSecure: z.boolean().optional(),
});

export async function POST(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const override = bodySchema.parse(await req.json().catch(() => ({})));
  const saved = await getSmtpConfig();

  if (!override.smtpHost && !saved) {
    return NextResponse.json({ ok: false, error: "SMTP is not configured." });
  }

  const config = {
    host: override.smtpHost ?? saved?.host ?? "",
    port: override.smtpPort ?? saved?.port ?? 587,
    secure: override.smtpSecure ?? saved?.secure ?? false,
    user: override.smtpUser ?? saved?.user ?? null,
    password: override.smtpPassword || saved?.password || null,
    fromAddress: override.smtpFromAddress ?? saved?.fromAddress ?? override.smtpUser ?? "forensicator@localhost",
  };

  const result = await sendMail(
    { to: override.to, subject: "Forensicator test alert", text: "This is a test of your Forensicator critical-finding email alert configuration." },
    config
  );

  return NextResponse.json(result);
}
