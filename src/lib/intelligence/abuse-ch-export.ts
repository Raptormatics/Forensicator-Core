/**
 * Downloads an abuse.ch bulk export (URLhaus, MalwareBazaar).
 *
 * abuse.ch retired the keyless bulk downloads in Oct 2026
 * (urlhaus.abuse.ch/downloads/csv_recent/ and bazaar.abuse.ch/export/csv/recent/
 * now answer 410 Gone). The replacements need an Auth-Key, placed in the
 * URL path: https://<service>/v2/files/exports/<Auth-Key>/recent.csv. The
 * CSV columns are unchanged.
 *
 * One abuse.ch Auth-Key (free at https://auth.abuse.ch/) works for every
 * abuse.ch service, so the key is looked up across all three abuse.ch
 * providers' configured keys, the feed's own first: an org that only saved
 * a ThreatFox key still gets its URLhaus feed.
 *
 * The key is part of the URL, so neither the URL nor anything containing it
 * goes into an error message or log line.
 */
import { resolveApiKey } from "./org-providers";

export type AbuseChFeed = "urlhaus" | "malwarebazaar";

const EXPORT_BASE: Record<AbuseChFeed, string> = {
  urlhaus: "https://urlhaus-api.abuse.ch/v2/files/exports",
  malwarebazaar: "https://mb-api.abuse.ch/v2/files/exports",
};

const LABEL: Record<AbuseChFeed, string> = {
  urlhaus: "URLhaus",
  malwarebazaar: "MalwareBazaar",
};

const ABUSE_CH_PROVIDERS = ["urlhaus", "malwarebazaar", "threatfox"] as const;

// URLhaus's recent.csv is ~30 MB.
const FETCH_TIMEOUT_MS = 5 * 60 * 1000;

export type AbuseChFeedErrorCode = "no_auth_key" | "invalid_auth_key" | "fetch_failed";

export class AbuseChFeedError extends Error {
  constructor(public code: AbuseChFeedErrorCode, message: string) {
    super(message);
    this.name = "AbuseChFeedError";
  }
}

/**
 * The org's key for this feed's provider, then its other abuse.ch provider
 * keys (resolveApiKey falls back to each provider's env var), then
 * ABUSECH_AUTH_KEY. With no organizationId (a scheduled sync), only the
 * env vars are consulted.
 */
export async function resolveAbuseChAuthKey(feed: AbuseChFeed, organizationId?: string): Promise<string | undefined> {
  const order = [feed, ...ABUSE_CH_PROVIDERS.filter((p) => p !== feed)];
  for (const provider of order) {
    const key = (await resolveApiKey(organizationId, provider))?.trim();
    if (key) return key;
  }
  return process.env.ABUSECH_AUTH_KEY?.trim() || undefined;
}

/** Fetches `<export base>/<Auth-Key>/<file>` and returns the body text. Throws AbuseChFeedError. */
export async function fetchAbuseChExport(feed: AbuseChFeed, file: string, organizationId?: string): Promise<string> {
  const label = LABEL[feed];
  const key = await resolveAbuseChAuthKey(feed, organizationId);
  if (!key) {
    throw new AbuseChFeedError(
      "no_auth_key",
      `The ${label} feed needs an abuse.ch Auth-Key. Get a free one at https://auth.abuse.ch/ and add it to the URLhaus, MalwareBazaar or ThreatFox provider.`
    );
  }
  if (!/^[A-Za-z0-9]+$/.test(key)) {
    throw new AbuseChFeedError("invalid_auth_key", `The configured abuse.ch Auth-Key isn't letters and digits only, so it can't be used for the ${label} feed.`);
  }

  let res: Response;
  try {
    res = await fetch(`${EXPORT_BASE[feed]}/${key}/${file}`, {
      headers: { "User-Agent": "Forensicator-Enterprise" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    const reason = err instanceof Error && err.name === "TimeoutError" ? "timed out" : "could not reach abuse.ch";
    throw new AbuseChFeedError("fetch_failed", `${label} feed download ${reason}.`);
  }
  if (res.status === 401 || res.status === 403) {
    throw new AbuseChFeedError("invalid_auth_key", `abuse.ch rejected the Auth-Key for the ${label} feed (${res.status}). Check the key at https://auth.abuse.ch/.`);
  }
  if (!res.ok) {
    throw new AbuseChFeedError("fetch_failed", `${label} feed fetch failed: ${res.status} ${res.statusText}`);
  }
  return res.text();
}

/** HTTP status for a sync route to answer a failed feed sync with. */
export function abuseChFeedErrorStatus(err: unknown): number {
  return err instanceof AbuseChFeedError && err.code === "no_auth_key" ? 400 : 502;
}

/** Splits `items` into arrays of at most `size` — keeps Prisma `in` lists and createMany batches under Postgres's bind-parameter limit. */
export function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}
