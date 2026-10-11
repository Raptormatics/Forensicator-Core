import type { ParsedEvent } from "../types";

// Windows Event Log — CSV export from Event Viewer or wevtutil
// Expected columns (flexible — we try multiple common column layouts):
//   Level,DateTime,Source,EventID,TaskCategory,... ,Description
// Also supports JSONL format (one JSON object per line) with EventID / TimeCreated / etc.

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const USER_RE = /Account Name:\s*(\S+)/i;
const PROC_RE = /(?:Process Name|New Process Name):\s*(.+)/i;
const CMD_RE  = /(?:Creator Process Name|Process Command Line):\s*(.+)/i;

function parseWindowsCsvLine(headers: string[], values: string[], lineNumber: number, raw: string): ParsedEvent {
  const get = (names: string[]) => {
    for (const n of names) {
      const idx = headers.findIndex((h) => h.toLowerCase().trim() === n.toLowerCase());
      if (idx >= 0 && values[idx]?.trim()) return values[idx].trim();
    }
    return null;
  };

  const tsRaw    = get(["datetime", "date and time", "time generated", "timecreated", "date"]);
  const eventId  = get(["event id", "eventid", "id"]);
  const level    = get(["level", "levelname", "type"]);
  const source   = get(["source", "provider", "sourcename"]);
  const desc     = get(["description", "message", "task category", "taskdisplayname"]);
  const user     = get(["user", "username"]);
  const computer = get(["computer", "computername", "machine"]);

  const timestamp = tsRaw ? (() => { try { return new Date(tsRaw); } catch { return null; } })() : null;
  const ip = desc ? (desc.match(IPV4_RE)?.[0] ?? null) : null;
  const userMatch = desc ? (desc.match(USER_RE)?.[1] ?? user) : user;
  const procMatch = desc ? (desc.match(PROC_RE)?.[1]?.trim() ?? null) : null;
  const cmdMatch  = desc ? (desc.match(CMD_RE)?.[1]?.trim() ?? null) : null;

  // Map common Event IDs to event types
  const eid = parseInt(eventId ?? "0", 10);
  let eventType: string | null = null;
  if ([4624, 4625, 4634, 4648, 4720, 4726].includes(eid)) eventType = "authentication";
  else if ([4688, 4689, 1, 5].includes(eid)) eventType = "process_create";
  else if ([4697, 7045].includes(eid)) eventType = "service_install";
  else if ([4698, 4702, 106].includes(eid)) eventType = "scheduled_task";
  else if ([4663, 4656].includes(eid)) eventType = "file_access";
  else if (level?.toLowerCase() === "error") eventType = "error";
  else if (level?.toLowerCase() === "warning") eventType = "warning";

  return {
    lineNumber,
    timestamp,
    sourceApp: "windows-event",
    eventType,
    srcIp: ip, dstIp: null, srcPort: null, dstPort: null,
    username: userMatch ?? null,
    domain: computer ?? null,
    process: procMatch,
    commandLine: cmdMatch,
    filePath: null, fileName: null,
    hashMd5: null, hashSha1: null, hashSha256: null,
    url: null, httpMethod: null, statusCode: eid || null,
    userAgent: null,
    message: desc ?? `EventID ${eventId} from ${source}`,
    raw,
    normalized: { eventId, level, source, computer, user, desc },
  } satisfies ParsedEvent;
}

function parseCsvRow(row: string): string[] {
  const result: string[] = [];
  let inQuote = false, cur = "";
  for (let i = 0; i < row.length; i++) {
    const c = row[i];
    if (c === '"') { inQuote = !inQuote; continue; }
    if (c === "," && !inQuote) { result.push(cur); cur = ""; continue; }
    cur += c;
  }
  result.push(cur);
  return result;
}

export function parseWindowsEvent(content: string): ParsedEvent[] {
  const lines = content.split("\n").filter((l) => l.trim());

  // Try JSON / NDJSON first
  if (lines[0]?.trim().startsWith("{") || lines[0]?.trim().startsWith("[")) {
    try {
      let objects: unknown[];
      const first = lines[0].trim();
      if (first.startsWith("[")) {
        objects = JSON.parse(content) as unknown[];
      } else {
        objects = lines.map((l) => JSON.parse(l)) as unknown[];
      }
      return objects.map((obj, i) => {
        const o = obj as Record<string, unknown>;
        const tsRaw = o["TimeCreated"] ?? o["time"] ?? o["datetime"] ?? o["Timestamp"];
        const ts = tsRaw ? (() => { try { return new Date(String(tsRaw)); } catch { return null; } })() : null;
        const eid = parseInt(String(o["EventID"] ?? o["Id"] ?? "0"), 10);
        const msg = String(o["Message"] ?? o["message"] ?? o["Description"] ?? "");
        const ip = msg.match(IPV4_RE)?.[0] ?? null;
        return {
          lineNumber: i + 1, timestamp: ts, sourceApp: "windows-event",
          eventType: eid === 4625 ? "auth_failure" : eid === 4688 ? "process_create" : null,
          srcIp: ip, dstIp: null, srcPort: null, dstPort: null,
          username: String(o["SubjectUserName"] ?? o["TargetUserName"] ?? "").replace(/^-$/, "") || null,
          domain: String(o["SubjectDomainName"] ?? o["ComputerName"] ?? "").replace(/^-$/, "") || null,
          process: String(o["ProcessName"] ?? o["NewProcessName"] ?? "").replace(/^-$/, "") || null,
          commandLine: String(o["CommandLine"] ?? "").replace(/^-$/, "") || null,
          filePath: null, fileName: null, hashMd5: null, hashSha1: null, hashSha256: null,
          url: null, httpMethod: null, statusCode: eid || null, userAgent: null,
          message: msg, raw: JSON.stringify(obj), normalized: o,
        } satisfies ParsedEvent;
      });
    } catch { /* fall through to CSV */ }
  }

  // CSV format
  const [headerLine, ...dataLines] = lines;
  const headers = parseCsvRow(headerLine);
  return dataLines
    .filter((l) => l.trim())
    .map((line, i) => parseWindowsCsvLine(headers, parseCsvRow(line), i + 2, line));
}
