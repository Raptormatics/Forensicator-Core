/**
 * Pulls a couple of extra, genuinely-collected fields out of an Evidence
 * row's raw JSON (the original per-row evidence object the collector
 * produced — see src/lib/upload/evidence-extractor.ts for the documented
 * shapes per finding type) to show alongside the match, instead of
 * repeating the IOC value itself on every row. Never fabricates a field —
 * only ever shows what the collector actually reported.
 */

const PRIORITY_KEYS = [
  "browser", "profile", "last_visit",
  "pid", "ppid", "parent_process", "executable_path", "creation_date",
  "process", "state",
  "source", "command",
  "device_desc", "friendly_name", "manufacturer",
  "file_path", "algorithm",
  "logon_type", "source_ip", "event_id",
];

const ALREADY_SHOWN = new Set([
  "url", "ip", "domain", "hash", "process_name", "command_line",
  "hostname", "username", "user", "time", "timestamp", "is_malicious",
]);

export type ForensicContextField = { key: string; value: string };

function humanizeKey(key: string): string {
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function isDisplayable(v: unknown): v is string | number | boolean {
  return (typeof v === "string" && v.trim().length > 0) || typeof v === "number" || typeof v === "boolean";
}

export function extractForensicContext(raw: unknown, limit = 2): ForensicContextField[] {
  if (!raw || typeof raw !== "object") return [];
  const obj = raw as Record<string, unknown>;
  const out: ForensicContextField[] = [];

  for (const key of PRIORITY_KEYS) {
    if (out.length >= limit) break;
    const v = obj[key];
    if (!isDisplayable(v)) continue;
    out.push({ key: humanizeKey(key), value: String(v) });
  }

  if (out.length < limit) {
    for (const [key, v] of Object.entries(obj)) {
      if (out.length >= limit) break;
      if (ALREADY_SHOWN.has(key) || PRIORITY_KEYS.includes(key)) continue;
      if (!isDisplayable(v)) continue;
      out.push({ key: humanizeKey(key), value: String(v) });
    }
  }

  return out;
}
