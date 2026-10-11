/**
 * Threat Intelligence provider interface.
 * Each provider implements this and returns a normalised result.
 */

export type ProviderResult = {
  found: boolean;
  reputation?: number;       // 0-100 maliciousness
  confidence?: number;       // 0-100
  malwareFamily?: string;
  threatType?: string;
  raw: Record<string, unknown>;
};

export interface TIProvider {
  name: string;
  supportsType(type: string): boolean;
  /** apiKey, when passed, overrides the provider's own env-var lookup (used for org-specific keys). */
  lookup(value: string, type: string, apiKey?: string): Promise<ProviderResult>;
}

// ── VirusTotal ────────────────────────────────────────────────────────────────
export class VirusTotalProvider implements TIProvider {
  name = "virustotal";
  supportsType(t: string) { return ["ip", "hash", "url", "domain"].includes(t); }

  async lookup(value: string, type: string, apiKeyOverride?: string): Promise<ProviderResult> {
    const apiKey = apiKeyOverride ?? process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) return { found: false, raw: { error: "no_api_key" } };

    const endpoint = this.buildEndpoint(value, type);
    if (!endpoint) return { found: false, raw: { error: "unsupported_value" } };

    const res = await fetch(endpoint, { headers: { "x-apikey": apiKey } });
    if (!res.ok) return { found: false, raw: { status: res.status, error: await res.text().catch(() => "") } };
    const json = await res.json() as Record<string, unknown>;
    const attr = (json?.data as Record<string, unknown>)?.attributes as Record<string, unknown> | undefined;
    const lastAnalysis = attr?.last_analysis_stats as Record<string, number> | undefined;
    const malicious = lastAnalysis?.malicious ?? 0;
    const total = Object.values(lastAnalysis ?? {}).reduce((a, b) => a + b, 0);
    const reputation = total > 0 ? Math.round((malicious / total) * 100) : 0;

    return {
      found: true,
      reputation,
      confidence: total > 10 ? 80 : 40,
      malwareFamily: (attr?.popular_threat_classification as Record<string, unknown>)?.suggested_threat_label as string | undefined,
      raw: json,
    };
  }

  private buildEndpoint(value: string, type: string): string | null {
    const BASE = "https://www.virustotal.com/api/v3";

    if (type === "hash") {
      return `${BASE}/files/${value}`;
    }

    if (type === "ip") {
      // Strip any accidental protocol prefix (e.g. "https://1.2.3.4")
      const ip = value.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0];
      return `${BASE}/ip_addresses/${ip}`;
    }

    if (type === "domain") {
      // Strip protocol and path — VT domains endpoint wants bare hostname only.
      // e.g. "https://evil.com/path" → "evil.com"
      const hostname = vtExtractHostname(value);
      return hostname ? `${BASE}/domains/${hostname}` : null;
    }

    if (type === "url") {
      // If the URL has no meaningful path/query, use the more reliable /domains
      // endpoint. Otherwise use /urls with base64url-encoded identifier.
      let parsed: URL | null = null;
      try { parsed = new URL(value); } catch { /* fall through */ }

      if (parsed) {
        const hasPath = parsed.pathname.replace(/^\/+/, "").length > 0;
        const hasQuery = parsed.search.length > 0;
        const ipHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname) || parsed.hostname.includes(":");

        if (!hasPath && !hasQuery && !ipHost) {
          // Pure domain URL — use domain endpoint (more reliable, no prior submission needed)
          return `${BASE}/domains/${parsed.hostname}`;
        }
        if (!hasPath && !hasQuery && ipHost) {
          // URL whose host is a bare IP with no path
          return `${BASE}/ip_addresses/${parsed.hostname}`;
        }
      }

      // Full URL with path/query — use VT's URL lookup (base64url-encoded)
      return `${BASE}/urls/${Buffer.from(value).toString("base64url")}`;
    }

    return null;
  }
}

/** Extract bare hostname from a value that may or may not have a protocol/path. */
function vtExtractHostname(value: string): string | null {
  // If it looks like a URL, parse it
  if (/^https?:\/\//i.test(value)) {
    try { return new URL(value).hostname; } catch { return null; }
  }
  // Already a bare hostname or hostname/path — take the first segment
  const host = value.split("/")[0].split(":")[0].trim();
  return host.length > 0 ? host : null;
}

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────
export class AbuseIPDBProvider implements TIProvider {
  name = "abuseipdb";
  // Supports ip directly, and urls/domains whose host resolves to a bare IP.
  supportsType(t: string) { return t === "ip" || t === "url"; }

  async lookup(value: string, type: string, apiKeyOverride?: string): Promise<ProviderResult> {
    const apiKey = apiKeyOverride ?? process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) return { found: false, raw: { error: "no_api_key" } };

    // If the value is a URL with a bare IP host, extract the IP.
    let ip = value;
    if (type === "url") {
      try {
        const { hostname } = new URL(value);
        const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":");
        if (!isIp) return { found: false, raw: { skipped: "url_host_is_domain" } };
        ip = hostname;
      } catch {
        return { found: false, raw: { error: "invalid_url" } };
      }
    }

    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    const res = await fetch(url, { headers: { Key: apiKey, Accept: "application/json" } });
    if (!res.ok) return { found: false, raw: { status: res.status } };
    const json = await res.json() as Record<string, unknown>;
    const d = (json.data as Record<string, unknown>) ?? {};

    return {
      found: true,
      reputation: typeof d.abuseConfidenceScore === "number" ? d.abuseConfidenceScore : undefined,
      confidence: 85,
      raw: json,
    };
  }
}

// ── URLHaus ───────────────────────────────────────────────────────────────────
export class URLHausProvider implements TIProvider {
  name = "urlhaus";
  supportsType(t: string) { return ["url", "domain", "hash"].includes(t); }

  async lookup(value: string, type: string): Promise<ProviderResult> {
    const body = type === "hash"
      ? `md5_hash=${encodeURIComponent(value)}`
      : `url=${encodeURIComponent(value)}`;

    const endpoint = type === "hash"
      ? "https://urlhaus-api.abuse.ch/v1/payload/"
      : "https://urlhaus-api.abuse.ch/v1/url/";

    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const json = await res.json() as Record<string, unknown>;
    const found = json.query_status !== "not_found" && json.query_status !== "no_results";

    return {
      found,
      reputation: found ? 90 : undefined,
      threatType: json.threat as string | undefined,
      raw: json,
    };
  }
}

// ── ThreatFox ─────────────────────────────────────────────────────────────────
export class ThreatFoxProvider implements TIProvider {
  name = "threatfox";
  supportsType(t: string) { return ["ip", "hash", "url", "domain"].includes(t); }

  async lookup(value: string, _type: string): Promise<ProviderResult> {
    const body = JSON.stringify({ query: "search_ioc", search_term: value });
    const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    const json = await res.json() as Record<string, unknown>;
    const found = json.query_status === "ok" && Array.isArray(json.data) && (json.data as unknown[]).length > 0;
    const first = found ? (json.data as Record<string, unknown>[])[0] : undefined;

    return {
      found,
      reputation: found ? 80 : undefined,
      malwareFamily: first?.malware as string | undefined,
      threatType: first?.threat_type as string | undefined,
      raw: json,
    };
  }
}

// ── MalwareBazaar ─────────────────────────────────────────────────────────────
export class MalwareBazaarProvider implements TIProvider {
  name = "malwarebazaar";
  supportsType(t: string) { return t === "hash"; }

  async lookup(value: string, _type: string): Promise<ProviderResult> {
    const body = `query=get_info&hash=${encodeURIComponent(value)}`;
    const res = await fetch("https://mb-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const json = await res.json() as Record<string, unknown>;
    const found = json.query_status === "ok";
    const d = found ? ((json.data as Record<string, unknown>[])[0]) : undefined;

    return {
      found,
      reputation: found ? 95 : undefined,
      malwareFamily: d?.signature as string | undefined,
      threatType: d?.tags ? String((d.tags as string[]).join(", ")) : undefined,
      raw: json,
    };
  }
}

// ── OTX (AlienVault) ─────────────────────────────────────────────────────────
export class OTXProvider implements TIProvider {
  name = "otx";
  supportsType(t: string) { return ["ip", "hash", "url", "domain"].includes(t); }

  async lookup(value: string, type: string, apiKeyOverride?: string): Promise<ProviderResult> {
    const apiKey = apiKeyOverride ?? process.env.OTX_API_KEY;
    const section = type === "hash" ? "file" : type === "url" ? "url" : type;
    const url = `https://otx.alienvault.com/api/v1/indicators/${section}/${encodeURIComponent(value)}/general`;
    const headers: Record<string, string> = apiKey ? { "X-OTX-API-KEY": apiKey } : {};
    const res = await fetch(url, { headers });
    if (!res.ok) return { found: false, raw: { status: res.status } };
    const json = await res.json() as Record<string, unknown>;
    const pulseCount = (json.pulse_info as Record<string, unknown>)?.count as number ?? 0;

    return {
      found: pulseCount > 0,
      reputation: Math.min(100, pulseCount * 10),
      confidence: 70,
      raw: json,
    };
  }
}

// ── Provider registry ─────────────────────────────────────────────────────────
export const ALL_PROVIDERS: TIProvider[] = [
  new VirusTotalProvider(),
  new AbuseIPDBProvider(),
  new URLHausProvider(),
  new ThreatFoxProvider(),
  new MalwareBazaarProvider(),
  new OTXProvider(),
];
