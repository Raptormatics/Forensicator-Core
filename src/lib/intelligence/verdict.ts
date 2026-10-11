/**
 * Turns a raw per-provider enrichment result into an unambiguous label —
 * "virustotal:ok" tells an analyst nothing about whether the indicator is
 * malicious (it just means the API call succeeded), so this parses each
 * provider's actual raw response shape (see src/lib/intelligence/providers.ts)
 * into the vendor's real conviction.
 */

export type VendorVerdict = {
  label: string;
  verdict: "malicious" | "suspicious" | "clean" | "unknown" | "error";
};

export const PROVIDER_LABEL: Record<string, string> = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  urlhaus: "URLhaus",
  urlhaus_feed: "URLhaus (local feed)",
  threatfox: "ThreatFox",
  malwarebazaar: "MalwareBazaar",
  otx: "OTX AlienVault",
};

const UNKNOWN: VendorVerdict = { label: "No data", verdict: "unknown" };

export function summarizeVendorVerdict(provider: string, status: string, response: unknown): VendorVerdict {
  if (status === "error") return { label: "Lookup error", verdict: "error" };
  if (status === "not_found") return { label: "No record found", verdict: "unknown" };
  if (status !== "ok" || !response || typeof response !== "object") return UNKNOWN;

  const r = response as Record<string, unknown>;

  switch (provider) {
    case "virustotal": {
      const attr = (r.data as Record<string, unknown> | undefined)?.attributes as Record<string, unknown> | undefined;
      const stats = attr?.last_analysis_stats as Record<string, number> | undefined;
      if (!stats) return UNKNOWN;
      const malicious = stats.malicious ?? 0;
      const suspicious = stats.suspicious ?? 0;
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      return {
        label: `${malicious}/${total} engines flagged malicious`,
        verdict: malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "clean",
      };
    }

    case "abuseipdb": {
      const score = (r.data as Record<string, unknown> | undefined)?.abuseConfidenceScore;
      if (typeof score !== "number") return UNKNOWN;
      return {
        label: `${score}% abuse confidence`,
        verdict: score >= 70 ? "malicious" : score >= 25 ? "suspicious" : "clean",
      };
    }

    // Both the live per-value API and the local bulk-feed cache only ever
    // return a hit for confirmed-malicious URLhaus entries — there's no
    // ambiguous "found but clean" state from this source.
    case "urlhaus":
    case "urlhaus_feed": {
      const threat = (r.threat as string | undefined) ?? undefined;
      return { label: threat ? `Confirmed: ${threat}` : "Confirmed malicious URL", verdict: "malicious" };
    }

    case "threatfox": {
      const first = Array.isArray(r.data) ? (r.data as Record<string, unknown>[])[0] : undefined;
      if (!first) return UNKNOWN;
      const label = [first.malware, first.threat_type].filter(Boolean).join(" — ");
      return { label: label || "Confirmed IOC", verdict: "malicious" };
    }

    case "malwarebazaar": {
      const first = Array.isArray(r.data) ? (r.data as Record<string, unknown>[])[0] : undefined;
      if (!first) return UNKNOWN;
      return { label: first.signature ? `Malware: ${first.signature}` : "Confirmed malware sample", verdict: "malicious" };
    }

    case "otx": {
      const count = (r.pulse_info as Record<string, unknown> | undefined)?.count as number | undefined ?? 0;
      return {
        label: `${count} threat-intel pulse${count !== 1 ? "s" : ""}`,
        verdict: count >= 3 ? "malicious" : count > 0 ? "suspicious" : "clean",
      };
    }

    default:
      return UNKNOWN;
  }
}

export const VERDICT_STYLE: Record<VendorVerdict["verdict"], string> = {
  malicious: "bg-red-900/40 text-red-300 border-red-800",
  suspicious: "bg-orange-900/40 text-orange-300 border-orange-800",
  clean: "bg-green-900/40 text-green-300 border-green-800",
  unknown: "bg-zinc-800 text-zinc-500 border-zinc-700",
  error: "bg-zinc-800 text-zinc-500 border-zinc-700",
};
