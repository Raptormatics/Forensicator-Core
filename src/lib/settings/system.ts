/**
 * Instance-wide settings, editable from Settings -> General.
 * Singleton row (src/prisma/schema.prisma: SystemSettings) — deliberately
 * narrow. Only settings safe to change live, without a process restart,
 * belong here; see the schema comment for why Redis connection info
 * stays env-var/restart-only instead.
 */
import path from "path";
import { prisma } from "@/lib/db/prisma";
import { decryptSecret } from "@/lib/crypto/secret-box";
import type { AiProvider, AiProviderConfig } from "@/lib/ai/provider";

const SINGLETON_ID = "singleton";

export async function getSystemSettings() {
  return prisma.systemSettings.findUnique({ where: { id: SINGLETON_ID } });
}

/** The instance's configured public URL (e.g. https://forensicator.tesco.com), or null if unset. */
export async function getAppDomain(): Promise<string | null> {
  const settings = await getSystemSettings();
  return settings?.appDomain ?? null;
}

/** DB override > REPORTS_DIR env var > default ./reports-output under the project root. */
export async function getReportsDir(): Promise<string> {
  const settings = await getSystemSettings();
  return (
    settings?.reportsDir ??
    process.env.REPORTS_DIR ??
    path.join(process.cwd(), "reports-output")
  );
}

/**
 * Forensicator AI provider config — DB-backed, schema defaults cover an
 * unconfigured instance. Decrypts the stored API key (if any) so callers
 * get something directly usable; never returns aiApiKeyEncrypted itself.
 */
export async function getAiConfig(): Promise<AiProviderConfig & { enabled: boolean }> {
  const settings = await getSystemSettings();
  return {
    enabled: settings?.aiEnabled ?? false,
    provider: (settings?.aiProvider as AiProvider) ?? "ollama",
    host: settings?.aiHost ?? "http://localhost:11434",
    model: settings?.aiModel ?? "mistral:7b-instruct",
    apiKey: settings?.aiApiKeyEncrypted ? decryptSecret(settings.aiApiKeyEncrypted) : null,
  };
}
