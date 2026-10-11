/**
 * Bulk companion to the per-evidence-row "Enrich" button (POST /api/ioc/enrich):
 * given a raw Evidence row, derive every plausible threat-intel indicator from
 * it — the dedicated url/ip/domain/hash columns when populated, plus a few
 * artifact-specific fallbacks into `raw` for types the extractor
 * (src/lib/upload/evidence-extractor.ts) never copied into a column. DNS Cache
 * Entries, for instance, only ever get their resolved domain/IP into `raw`
 * (as `entry`/`name`/`data`), never into Evidence.domain/Evidence.ip.
 */

export type IocType = "ip" | "hash" | "url" | "domain" | "email";
export type ExtractedIoc = { value: string; type: IocType };

type EvidenceLike = {
  type: string;
  url: string | null;
  ip: string | null;
  domain: string | null;
  hash: string | null;
  raw: unknown;
};

const WILDCARD_ADDRS = new Set(["::", "0.0.0.0", "::1", "127.0.0.1"]);
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

// DNS Cache "data"/ARP "ip_address" fields can hold a resolved *hostname*
// instead of an address (e.g. reverse-lookup PTR entries resolving to
// "host.local") — verify the value is actually address-shaped before it's
// ever treated as one, so a hostname never gets mislabeled as an IP indicator.
function looksLikeIp(v: string): boolean {
  if (IPV4_RE.test(v)) return v.split(".").every((o) => Number(o) <= 255);
  return v.includes(":") && /^[0-9a-fA-F:]+$/.test(v);
}

// Only public, routable addresses are worth spending enrichment quota on —
// LAN traffic, loopback, and multicast/link-local noise (common in ARP/TCP
// artifacts) will never have a threat-intel verdict.
function isPubliclyRoutableIp(ip: string): boolean {
  const v = ip.trim();
  if (!v || !looksLikeIp(v) || WILDCARD_ADDRS.has(v)) return false;
  if (/^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(v)) return false; // RFC1918 + link-local + loopback
  if (/^f[cd]/i.test(v)) return false; // IPv6 unique-local (fc00::/7)
  if (/^fe[89ab]/i.test(v)) return false; // IPv6 link-local (fe80::/10)
  if (/^ff/i.test(v)) return false; // IPv6 multicast (ff00::/8)
  return true;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

// Reverse-DNS PTR query names ("56.0.0.10.in-addr.arpa") aren't real domains —
// no threat-intel provider can return anything meaningful for one.
function isRealDomain(domain: string): boolean {
  const v = domain.toLowerCase();
  return v !== "localhost" && !v.endsWith(".in-addr.arpa") && !v.endsWith(".ip6.arpa");
}

export function extractIocsFromEvidenceRow(row: EvidenceLike): ExtractedIoc[] {
  const out: ExtractedIoc[] = [];
  const seen = new Set<string>();
  const push = (value: string | undefined | null, type: IocType) => {
    if (!value) return;
    const v = value.trim().slice(0, 500);
    if (!v) return;
    const key = `${type}:${v}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ value: v, type });
  };

  // Generic pass — whatever's already on the dedicated columns, regardless of
  // artifact type. This is what covers "any other artifact that can hold an
  // indicator" without needing type-specific handling for every one.
  if (row.url && !row.url.startsWith("file://")) push(row.url, "url");
  if (row.hash) push(row.hash, "hash");
  if (row.domain && isRealDomain(row.domain)) push(row.domain, "domain");
  if (row.ip && isPubliclyRoutableIp(row.ip)) push(row.ip, "ip");

  // Artifact-specific fallbacks into raw, for types whose extractor never
  // populated a column at all.
  const raw = row.raw && typeof row.raw === "object" ? (row.raw as Record<string, unknown>) : null;
  if (raw) {
    const ft = row.type.toLowerCase();
    if (ft.includes("dns")) {
      const domain = str(raw.entry) ?? str(raw.name);
      if (domain && isRealDomain(domain)) push(domain, "domain");
      const ip = str(raw.data);
      if (ip && isPubliclyRoutableIp(ip)) push(ip, "ip");
    }
    if (ft.includes("neighbour") || ft.includes("neighbor") || ft.includes("arp")) {
      const ip = str(raw.ip_address);
      if (ip && isPubliclyRoutableIp(ip)) push(ip, "ip");
    }
    if (ft.includes("tcp") || ft.includes("connection")) {
      const remote = str(raw.remote_address);
      if (remote && isPubliclyRoutableIp(remote)) push(remote, "ip");
    }
  }

  return out;
}
