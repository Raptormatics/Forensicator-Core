import type { IocHit, ParsedEvent } from "./types";

// ─────────────────────────────────────────────────────────────────────────────
// IOC regex patterns
// ─────────────────────────────────────────────────────────────────────────────

const RE_IPV4    = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b/g;
const RE_DOMAIN  = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|fr|ru|cn|info|biz|xyz|top|online|site|store|shop|club|app|dev|ai|me|us|ca|au|in|jp|br|nl|se|no|fi|dk|pl|cz|sk|hu|ro|bg|hr|rs|si|lt|lv|ee|is|at|ch|be|pt|es|it|gr|tr|sa|ae|il|za|ng|ke|gh|eg|ma|tn|dz|ly|sd|et|tz|ug|sn|ci|cm|mz|ao|zw|bw|rw|mw|zm|na|ls|sz|mg|mu|re|sc|km|cv|st|gw|gn|sl|lr|tg|bj|bf|ml|ne|mr|gm|eh)\b/gi;
const RE_URL     = /https?:\/\/[^\s"'<>\]]+/g;
const RE_MD5     = /\b[a-fA-F0-9]{32}\b/g;
const RE_SHA1    = /\b[a-fA-F0-9]{40}\b/g;
const RE_SHA256  = /\b[a-fA-F0-9]{64}\b/g;
const RE_PROC    = /\b[A-Za-z0-9_\-]+\.exe\b/gi;
const RE_WINPATH = /[A-Za-z]:\\[^\s"'<>|:*?]{2,}/g;
const RE_NIXPATH = /\/(?:tmp|home|var|etc|usr|opt|proc|dev|run|sys|boot|lib|bin|sbin|srv|media|mnt)[^\s"'<>|]{1,}/g;
const RE_EMAIL   = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;

function uniq(arr: string[]): string[] {
  return [...new Set(arr)];
}

function extractFromText(text: string): IocHit[] {
  const hits: IocHit[] = [];

  // URLs first (superset of IPs/domains — avoids double-counting inside URLs)
  const urls = uniq(text.match(RE_URL) ?? []);
  urls.forEach((v) => hits.push({ type: "url", value: v }));

  // IPs
  const ips = uniq(text.match(RE_IPV4) ?? []).filter(
    (ip) => !["0.0.0.0", "255.255.255.255", "127.0.0.1"].includes(ip)
  );
  ips.forEach((v) => hits.push({ type: "ip", value: v }));

  // Domains — skip anything that looks like it came inside a URL already
  const urlTexts = urls.join(" ");
  const domains = uniq(text.match(RE_DOMAIN) ?? []).filter(
    (d) => !urlTexts.includes(d) && !ips.includes(d)
  );
  domains.forEach((v) => hits.push({ type: "domain", value: v.toLowerCase() }));

  // Hashes (longest first to avoid SHA1 matching inside SHA256)
  uniq(text.match(RE_SHA256) ?? []).forEach((v) => hits.push({ type: "hash_sha256", value: v.toLowerCase() }));
  uniq(text.match(RE_SHA1) ?? []).forEach((v) => hits.push({ type: "hash_sha1",   value: v.toLowerCase() }));
  uniq(text.match(RE_MD5) ?? []).forEach((v) =>   hits.push({ type: "hash_md5",   value: v.toLowerCase() }));

  // Processes
  uniq(text.match(RE_PROC) ?? []).forEach((v) => hits.push({ type: "process", value: v.toLowerCase() }));

  // File paths
  uniq(text.match(RE_WINPATH) ?? []).forEach((v) => hits.push({ type: "filepath", value: v }));
  uniq(text.match(RE_NIXPATH) ?? []).forEach((v) => hits.push({ type: "filepath", value: v }));

  // Emails
  uniq(text.match(RE_EMAIL) ?? []).forEach((v) => hits.push({ type: "email", value: v.toLowerCase() }));

  return hits;
}

/**
 * Aggregate IOC hits across all events, counting occurrences.
 */
export function extractIocs(events: ParsedEvent[]): Map<string, { type: string; value: string; count: number }> {
  const map = new Map<string, { type: string; value: string; count: number }>();

  for (const ev of events) {
    // Prefer structured fields over raw regex for IPs/hashes to reduce noise
    const structuredHits: IocHit[] = [];

    if (ev.srcIp)     structuredHits.push({ type: "ip",         value: ev.srcIp });
    if (ev.dstIp)     structuredHits.push({ type: "ip",         value: ev.dstIp });
    if (ev.domain)    structuredHits.push({ type: "domain",     value: ev.domain.toLowerCase() });
    if (ev.url)       structuredHits.push({ type: "url",        value: ev.url });
    if (ev.hashMd5)   structuredHits.push({ type: "hash_md5",   value: ev.hashMd5.toLowerCase() });
    if (ev.hashSha1)  structuredHits.push({ type: "hash_sha1",  value: ev.hashSha1.toLowerCase() });
    if (ev.hashSha256)structuredHits.push({ type: "hash_sha256",value: ev.hashSha256.toLowerCase() });
    if (ev.process)   structuredHits.push({ type: "process",    value: ev.process.toLowerCase() });
    if (ev.filePath)  structuredHits.push({ type: "filepath",   value: ev.filePath });
    if (ev.username)  structuredHits.push({ type: "username",   value: ev.username.toLowerCase() });

    // Also run regex on the raw line for anything missed
    const rawHits = extractFromText(ev.raw);

    for (const hit of [...structuredHits, ...rawHits]) {
      if (!hit.value || hit.value.length < 2) continue;
      const key = `${hit.type}::${hit.value}`;
      const existing = map.get(key);
      if (existing) {
        existing.count++;
      } else {
        map.set(key, { ...hit, count: 1 });
      }
    }
  }

  return map;
}
