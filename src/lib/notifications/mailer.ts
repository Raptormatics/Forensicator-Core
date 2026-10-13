/**
 * SMTP email — the single notification channel Core ships (Enterprise
 * adds Slack/Teams/webhook alerting as a pure addition on top of this).
 * getSmtpConfig() mirrors settings/system.ts's getAiConfig(): read the
 * SystemSettings singleton fresh (no restart needed to pick up a change),
 * decrypt the password via the same AES-256-GCM secret-box every other
 * stored credential in this app uses.
 */
import nodemailer from "nodemailer";
import { getSystemSettings } from "@/lib/settings/system";
import { decryptSecret } from "@/lib/crypto/secret-box";

export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  user: string | null;
  password: string | null;
  fromAddress: string;
}

export async function getSmtpConfig(): Promise<SmtpConfig | null> {
  const settings = await getSystemSettings();
  if (!settings?.smtpHost) return null;

  return {
    host: settings.smtpHost,
    port: settings.smtpPort ?? 587,
    secure: settings.smtpSecure,
    user: settings.smtpUser ?? null,
    password: settings.smtpPasswordEncrypted ? decryptSecret(settings.smtpPasswordEncrypted) : null,
    fromAddress: settings.smtpFromAddress ?? settings.smtpUser ?? "forensicator@localhost",
  };
}

export type SendMailResult = { ok: true } | { ok: false; error: string };

export async function sendMail(
  opts: { to: string; subject: string; text: string },
  configOverride?: SmtpConfig
): Promise<SendMailResult> {
  const config = configOverride ?? (await getSmtpConfig());
  if (!config) return { ok: false, error: "SMTP is not configured." };

  try {
    const transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: config.user ? { user: config.user, pass: config.password ?? undefined } : undefined,
    });
    await transporter.sendMail({ from: config.fromAddress, to: opts.to, subject: opts.subject, text: opts.text });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
