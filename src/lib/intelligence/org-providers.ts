/**
 * Per-organization threat-intel provider configuration.
 *
 * Covers ALL providers (not just the ones needing a key) so an org can see
 * and toggle every provider from the dashboard — none of them are invisible
 * defaults baked only into the codebase.
 *
 * - virustotal / abuseipdb / otx / urlhaus / threatfox / malwarebazaar: need
 *   an API key. An org's own key (if set and enabled) is used; otherwise
 *   falls back to the global env-var key.
 *
 * urlhaus/threatfox/malwarebazaar were free and keyless until abuse.ch
 * rolled out mandatory "Auth-Key" authentication across all their APIs
 * (confirmed directly against the live API — every request now returns
 * {"query_status":"unknown_auth_key"}/{"error":"Unauthorized"} without
 * one). Free to register for at https://auth.abuse.ch/.
 *
 * With no organizationId (e.g. a platform_admin acting outside any org), or
 * with no override row for a provider, everything defaults to enabled.
 */
import { prisma } from "@/lib/db/prisma";
import { encryptSecret, decryptSecret } from "@/lib/crypto/secret-box";
import { ALL_PROVIDERS } from "./providers";

export const KEYED_PROVIDERS = ["virustotal", "abuseipdb", "otx", "urlhaus", "threatfox", "malwarebazaar"] as const;
export type KeyedProvider = (typeof KEYED_PROVIDERS)[number];

/** Canonical provider list, sourced from the actual provider registry so it can't drift. */
export const ALL_PROVIDER_NAMES = ALL_PROVIDERS.map((p) => p.name);

const ENV_VAR: Record<KeyedProvider, string> = {
  virustotal: "VIRUSTOTAL_API_KEY",
  abuseipdb: "ABUSEIPDB_API_KEY",
  otx: "OTX_API_KEY",
  urlhaus: "URLHAUS_AUTH_KEY",
  threatfox: "THREATFOX_AUTH_KEY",
  malwarebazaar: "MALWAREBAZAAR_AUTH_KEY",
};

export function isKeyedProvider(provider: string): provider is KeyedProvider {
  return (KEYED_PROVIDERS as readonly string[]).includes(provider);
}

function hasGlobalFallback(provider: KeyedProvider): boolean {
  const v = process.env[ENV_VAR[provider]];
  return Boolean(v) && v !== "your_otx_api_key_here";
}

/** Resolve the API key to use for a given org + provider — org key first, then env fallback. */
export async function resolveApiKey(
  organizationId: string | undefined,
  provider: string
): Promise<string | undefined> {
  if (!isKeyedProvider(provider)) return undefined;

  if (organizationId) {
    const row = await prisma.orgThreatIntelProvider.findUnique({
      where: { organizationId_provider: { organizationId, provider } },
    });
    if (row?.enabled && row.encryptedApiKey) {
      prisma.orgThreatIntelProvider
        .update({ where: { id: row.id }, data: { lastUsedAt: new Date() } })
        .catch(() => {});
      return decryptSecret(row.encryptedApiKey);
    }
  }

  return process.env[ENV_VAR[provider]] || undefined;
}

/** Whether a provider should run at all for this org's enrichment requests. Default: enabled. */
export async function isProviderEnabledForOrg(
  organizationId: string | undefined,
  provider: string
): Promise<boolean> {
  if (!organizationId) return true;
  const row = await prisma.orgThreatIntelProvider.findUnique({
    where: { organizationId_provider: { organizationId, provider } },
  });
  return row?.enabled ?? true;
}

export type OrgProviderStatus = {
  provider: string;
  requiresKey: boolean;
  enabled: boolean;
  configured: boolean; // this org has its own key set (only meaningful when requiresKey)
  usingGlobalFallback: boolean; // no org key, but a global env key exists (only meaningful when requiresKey)
  keyLast4: string | null;
  lastUsedAt: string | null;
  lastError: string | null;
};

export async function listOrgProviderStatus(organizationId: string | undefined): Promise<OrgProviderStatus[]> {
  const rows = organizationId
    ? await prisma.orgThreatIntelProvider.findMany({ where: { organizationId } })
    : [];
  const byProvider = new Map(rows.map((r) => [r.provider, r]));

  return ALL_PROVIDER_NAMES.map((provider) => {
    const row = byProvider.get(provider);
    const requiresKey = isKeyedProvider(provider);
    return {
      provider,
      requiresKey,
      enabled: row?.enabled ?? true,
      configured: requiresKey ? Boolean(row?.encryptedApiKey) : true,
      usingGlobalFallback: requiresKey ? !row?.encryptedApiKey && hasGlobalFallback(provider) : false,
      keyLast4: row?.keyLast4 ?? null,
      lastUsedAt: row?.lastUsedAt?.toISOString() ?? null,
      lastError: row?.lastError ?? null,
    };
  });
}

export async function setOrgProviderKey(
  organizationId: string,
  provider: KeyedProvider,
  apiKey: string,
  enabled: boolean
): Promise<void> {
  await prisma.orgThreatIntelProvider.upsert({
    where: { organizationId_provider: { organizationId, provider } },
    create: {
      organizationId,
      provider,
      encryptedApiKey: encryptSecret(apiKey),
      keyLast4: apiKey.slice(-4),
      enabled,
    },
    update: {
      encryptedApiKey: encryptSecret(apiKey),
      keyLast4: apiKey.slice(-4),
      enabled,
      lastError: null,
    },
  });
}

/** Enable/disable any provider (keyed or keyless) for this org. Creates an override row if none exists. */
export async function setOrgProviderEnabled(
  organizationId: string,
  provider: string,
  enabled: boolean
): Promise<void> {
  await prisma.orgThreatIntelProvider.upsert({
    where: { organizationId_provider: { organizationId, provider } },
    create: { organizationId, provider, enabled, encryptedApiKey: null, keyLast4: null },
    update: { enabled },
  });
}

/** Clear this org's override for a provider entirely — reverts to default (enabled, global key fallback if any). */
export async function clearOrgProviderOverride(organizationId: string, provider: string): Promise<void> {
  await prisma.orgThreatIntelProvider.deleteMany({ where: { organizationId, provider } });
}
