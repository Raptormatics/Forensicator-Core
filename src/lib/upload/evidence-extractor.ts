/**
 * evidence-extractor.ts
 *
 * Converts a parsed finding's evidence[] array into normalised Evidence rows
 * and a TimelineEvent for each finding's timeline[] entry.
 *
 * Designed for the real Forensicator collector JSON structure:
 *   - browser-history  : url, user, browser, last_visit, is_malicious
 *   - processes        : name, pid, command_line, executable_path, username, creation_date
 *   - tcp-connections  : local_address, remote_address, process, state
 *   - ps-history       : source, command
 *   - ioc-url          : url, user, time, browser
 *   - usb-devices      : device_desc, friendly_name, manufacturer
 *   - hash-match       : hash, file_path, algorithm
 *   - event logs       : username, logon_type, source_ip / logon_ip / client /
 *                        source_network_address (field name varies per event type), etc.
 */

import type { FindingJson } from "@/types/findings";
import type { JsonObject } from "@/types/json";
import { normalizeSeverity } from "@/lib/severity";

// ── Output types ─────────────────────────────────────────────────────────────

export type EvidenceInsert = {
  investigationId: string;
  findingId: string; // DB UUID of the Finding row
  type: string;
  source: string | null;
  timestamp: Date | null;
  hostname: string | null;
  username: string | null;
  raw: JsonObject;
  searchableText: string;
  hash: string | null;
  ip: string | null;
  domain: string | null;
  url: string | null;
  processName: string | null;
  commandLine: string | null;
};

export type TimelineEventInsert = {
  investigationId: string;
  findingId: string;
  timestamp: Date;
  title: string;
  description: string | null;
  category: string;
  severity: string;
  sourceType: string;
  evidenceId: string | null;
  metadata: JsonObject | null;
};

// ── Public API ────────────────────────────────────────────────────────────────

export function extractEvidence(
  finding: FindingJson,
  investigationId: string,
  findingDbId: string,
  sourceCategory: string | null
): EvidenceInsert[] {
  return (finding.evidence as JsonObject[]).map((row) =>
    buildEvidenceRow(row, finding, investigationId, findingDbId, sourceCategory)
  );
}

// finding.timeline[] entries carry an optional event_type ("evidence" | "collection")
// as of the collector fix that stopped stamping every finding's timeline with the
// collection time (nearly identical across ~90 findings in one run, and useless for
// reconstructing when things actually happened) and started pulling a real timestamp
// out of the finding's own evidence rows where one exists. Older collector versions,
// and findings with no time-shaped evidence field, omit event_type entirely — mapped
// to the original "finding_timeline" sourceType so existing data/filters don't shift
// under anyone. Only entries the collector explicitly marked get a more specific
// sourceType, which is what lets the Timeline UI offer a "real events only" filter
// instead of drowning every finding's genuine event in ~90 findings' worth of noise.
function timelineSourceType(eventType: string | null): string {
  if (eventType === "evidence") return "finding_evidence_time";
  if (eventType === "collection") return "finding_collected";
  return "finding_timeline";
}

export function extractTimelineEvents(
  finding: FindingJson,
  investigationId: string,
  findingDbId: string
): TimelineEventInsert[] {
  const events: TimelineEventInsert[] = [];

  for (const entry of finding.timeline as JsonObject[]) {
    const ts = parseTimestamp(str(entry.timestamp));
    if (!ts) continue;

    events.push({
      investigationId,
      findingId: findingDbId,
      timestamp: ts,
      title: str(entry.event) ?? finding.finding_type,
      description: null,
      category: normalisedCategory(finding),
      severity: normalizeSeverity(finding.severity),
      sourceType: timelineSourceType(str(entry.event_type)),
      evidenceId: null,
      metadata: null,
    });
  }

  return events;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function buildEvidenceRow(
  row: JsonObject,
  finding: FindingJson,
  investigationId: string,
  findingDbId: string,
  sourceCategory: string | null
): EvidenceInsert {
  const host = finding.host as JsonObject | undefined;

  // Base fields that apply to all finding types.
  const hostname =
    str(row.hostname) ??
    str(row.host) ??
    str(host?.hostname) ??
    null;

  // Only an account the row itself names. finding.host.username is the
  // account the collector ran under (the responder, on a remote collection),
  // so falling back to it attributed every user-less row — firewall rules,
  // DNS entries, services — to that account and made it correlate across
  // every host in a case.
  const username =
    str(row.username) ??
    str(row.user) ??
    str(row.logon_user) ??
    null;

  // ── IOC field extraction by finding type ───────────────────────────────────
  const url = extractUrl(row, finding.finding_type);
  const ip = extractIp(row, finding.finding_type);
  const domain = extractDomain(row, finding.finding_type, url);
  const processName = extractProcessName(row, finding.finding_type);
  const commandLine = extractCommandLine(row, finding.finding_type);
  const hash = extractHash(row, finding.finding_type);

  // ── Timestamp ─────────────────────────────────────────────────────────────
  const timestamp =
    parseTimestamp(str(row.last_visit)) ??
    parseTimestamp(str(row.creation_date)) ??
    parseTimestamp(str(row.time)) ??
    parseTimestamp(str(row.timestamp)) ??
    parseTimestamp(str(row.StartExecutionTime)) ??
    parseTimestamp(str(row.event_time)) ??
    null;

  // ── Searchable text ───────────────────────────────────────────────────────
  const searchableText = buildSearchText([
    url, ip, domain, processName, commandLine, hash, hostname, username,
    str(row.name), str(row.friendly_name), str(row.device_desc),
    str(row.source), str(row.command), str(row.browser),
    str(row.file_path), str(row.description), str(row.service_name),
    // Sigma-specific fields
    str(row.rule_title), str(row.rule_tags), str(row.rule_level),
    str(row.log_name), str(row.event_id), str(row.rule_file), str(row.rule_id),
    finding.finding_type, finding.category ?? "",
  ]);

  // For sigma evidence, log_name is the most meaningful source
  const isSigma = finding.finding_type.toLowerCase().includes("sigma");
  const source = isSigma
    ? (str(row.log_name) ?? sourceCategory ?? str((finding.source as JsonObject)?.artifact) ?? null)
    : (sourceCategory ?? str((finding.source as JsonObject)?.artifact) ?? null);

  return {
    investigationId,
    findingId: findingDbId,
    type: finding.finding_type,
    source,
    timestamp,
    hostname,
    username,
    raw: row,
    searchableText,
    hash,
    ip,
    domain,
    url,
    processName,
    commandLine,
  };
}

// ── Field extractors ─────────────────────────────────────────────────────────

// Loosely matches a URL embedded anywhere in free text (e.g. inside a shell
// command like "curl http://182.120.10.85:50338/i") — stops at whitespace or
// common trailing punctuation/quote characters rather than requiring the URL
// to be the entire field value.
const COMMAND_URL_RE = /https?:\/\/[^\s"'`)>,;]+/i;
const COMMAND_IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/;

/** Pulls a URL, or failing that a bare IPv4, out of a free-text command string. */
function extractIocFromCommandText(text: string | null): { url: string | null; ip: string | null } {
  if (!text) return { url: null, ip: null };
  const urlMatch = text.match(COMMAND_URL_RE);
  if (urlMatch) return { url: urlMatch[0], ip: null };
  const ipMatch = text.match(COMMAND_IPV4_RE);
  if (ipMatch) return { url: null, ip: ipMatch[0] };
  return { url: null, ip: null };
}

function commandText(row: JsonObject): string | null {
  return str(row.command) ?? str(row.command_line) ?? null;
}

function extractUrl(row: JsonObject, findingType: string): string | null {
  const ft = findingType.toLowerCase();
  // Scoped to "powershell" specifically — NOT the broader "history" match
  // extractCommandLine() below uses, which would also catch "Browser
  // History"/"RDP Authentication History" rows that have their own `url`
  // field (or none at all) and no `command`/`command_line` to scan.
  if (ft.includes("powershell")) {
    return extractIocFromCommandText(commandText(row)).url ?? str(row.url) ?? null;
  }
  return str(row.url) ?? null;
}

function extractIp(row: JsonObject, findingType: string): string | null {
  const ft = findingType.toLowerCase();
  // These two must come before the tcp/connection/network check below —
  // "Network Hops (Non-local Routes)" contains "network" and would
  // otherwise be swallowed by that broader, unrelated branch (it has no
  // remote_address/local_address field, just next_hop).
  // DNS Cache Entries: `data` is the resolved address for the cached name.
  if (ft.includes("dns")) {
    return str(row.data) ?? null;
  }
  // Network Hops (Non-local Routes) / IP Hops (Infinite Lifetime Routes):
  // `next_hop` is the gateway address for that route. "0.0.0.0" means "no
  // gateway / directly connected" — not a real indicator.
  if (ft.includes("hop") || ft.includes("route")) {
    const nextHop = str(row.next_hop);
    return nextHop && nextHop !== "0.0.0.0" ? nextHop : null;
  }
  if (ft.includes("tcp") || ft.includes("connection") || ft.includes("network")) {
    const remote = str(row.remote_address);
    if (remote && remote !== "::" && remote !== "0.0.0.0" && !remote.startsWith("::")) {
      return remote;
    }
    return str(row.local_address) ?? null;
  }
  if (ft.includes("powershell")) {
    return extractIocFromCommandText(commandText(row)).ip;
  }
  const candidate =
    str(row.source_ip) ??
    str(row.remote_address) ??
    str(row.ip_address) ??
    str(row.ip) ??
    // RDP Login Events / RDP Authentication History / Successful & Failed
    // Logon Events each name their source-address field differently.
    str(row.logon_ip) ??
    str(row.client) ??
    str(row.source_network_address) ??
    null;
  // Windows event logs use "-" as a placeholder for "no source address"
  // (e.g. local/SYSTEM logons) — not a real indicator.
  return candidate && candidate !== "-" ? candidate : null;
}

function extractDomain(row: JsonObject, findingType: string, url: string | null): string | null {
  const ft = findingType.toLowerCase();
  // DNS Cache Entries: `entry`/`name` carry the queried/cached hostname
  // directly — no URL to parse it out of.
  if (ft.includes("dns")) {
    const domain = str(row.entry) ?? str(row.name);
    if (domain && domain.toLowerCase() !== "localhost") return domain;
  }
  if (url) {
    try {
      const { hostname } = new URL(url);
      // Don't store IPs as domains.
      if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname === "localhost") return null;
      return hostname || null;
    } catch {
      return null;
    }
  }
  return null;
}

// Finding types whose rows are programs — running processes, services,
// scheduled tasks, startup/persistence entries, executables — across the
// Windows, Linux and macOS collectors. Only these rows' generic `name` field
// is a process/program name; on every other type it is something else
// (a firewall rule, an environment variable, an account, a DNS-cache entry,
// an adapter), and treating it as a process name made those values the bulk
// of all cross-host "shared process" correlations.
const PROGRAM_LISTING_RE =
  /\b(process(es)?|programs?|services?|tasks?|startup|autoruns?|executables?|binar(y|ies)|launch|login items|cron|systemd|timers?|persistence|units?|kernel (modules|extensions)|containers?)\b/i;

function extractProcessName(row: JsonObject, findingType: string): string | null {
  // For sigma findings, the rule title is the most descriptive name
  if (findingType.toLowerCase().includes("sigma")) {
    return str(row.rule_title) ?? str(row.name) ?? str(row.process) ?? null;
  }
  const isProgramListing = PROGRAM_LISTING_RE.test(findingType) && !/principal/i.test(findingType);
  return (
    (isProgramListing ? str(row.name) : null) ??
    str(row.process) ??
    str(row.process_name) ??
    str(row.service_name) ??
    str(row.task_name) ??
    null
  );
}

function extractCommandLine(row: JsonObject, findingType: string): string | null {
  const ft = findingType.toLowerCase();
  // PowerShell history: command field
  if (ft.includes("powershell") || ft.includes("ps-history") || ft.includes("history")) {
    return str(row.command) ?? str(row.command_line) ?? null;
  }
  return (
    str(row.command_line) ??
    str(row.command) ??
    str(row.arguments) ??
    null
  );
}

function extractHash(row: JsonObject, findingType: string): string | null {
  return (
    str(row.sha256) ??
    str(row.md5) ??
    str(row.sha1) ??
    str(row.hash) ??
    str(row.file_hash) ??
    null
  );
}

// ── Utility ───────────────────────────────────────────────────────────────────

function str(value: unknown): string | null {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number") return String(value);
  return null;
}

function parseTimestamp(value: string | null): Date | null {
  if (!value) return null;
  // Handle "N/A" placeholders from collector
  if (value.toLowerCase().includes("n/a")) return null;
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
}

function normalisedCategory(finding: FindingJson): string {
  const src = (finding.source as JsonObject | undefined);
  const artifact = str(src?.artifact)?.toLowerCase() ?? "";
  const ft = finding.finding_type.toLowerCase();
  const cat = (finding.category ?? "").toLowerCase();

  if (ft.includes("browser") || artifact.includes("browser")) return "browser";
  if (ft.includes("powershell") || ft.includes("ps-history")) return "powershell";
  if (ft.includes("process")) return "execution";
  if (ft.includes("tcp") || ft.includes("network") || ft.includes("connection")) return "network";
  if (ft.includes("rdp") || ft.includes("lateral")) return "lateral-movement";
  if (ft.includes("login") || ft.includes("logon") || ft.includes("account")) return "credential-access";
  if (ft.includes("usb") || ft.includes("removable")) return "usb";
  if (ft.includes("service")) return "persistence";
  if (ft.includes("task") || ft.includes("scheduled")) return "persistence";
  if (ft.includes("sigma")) return "detection";
  if (ft.includes("hash") || ft.includes("ioc") || ft.includes("malicious")) return "malware";
  if (cat.includes("lateral")) return "lateral-movement";
  if (cat.includes("execution")) return "execution";
  if (cat.includes("defense")) return "defense-evasion";
  if (cat.includes("collection")) return "collection";
  return cat.replace(/\s+/g, "-");
}

function buildSearchText(parts: (string | null)[]): string {
  return Array.from(new Set(parts.filter(Boolean) as string[]))
    .join(" ")
    .slice(0, 50000);
}
