import type { ParsedEvent } from "../types";

// Custom JSON / NDJSON log parser.
// Handles:  - NDJSON (one JSON object per line)
//           - JSON array [ {...}, {...} ]

function toStr(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s === "-" || s === "" ? null : s;
}
function toInt(v: unknown): number | null {
  if (v === null || v === undefined) return null;
  const n = parseInt(String(v), 10);
  return isNaN(n) ? null : n;
}
function toDate(v: unknown): Date | null {
  if (!v) return null;
  try { const d = new Date(String(v)); return isNaN(d.getTime()) ? null : d; }
  catch { return null; }
}

export function parseCustomJson(content: string): ParsedEvent[] {
  let objects: unknown[];
  const trimmed = content.trim();

  try {
    if (trimmed.startsWith("[")) {
      objects = JSON.parse(trimmed) as unknown[];
    } else {
      // NDJSON
      objects = trimmed.split("\n")
        .filter((l) => l.trim().startsWith("{"))
        .map((l) => JSON.parse(l));
    }
  } catch {
    return [{
      lineNumber: 1, timestamp: null, sourceApp: "custom-json", eventType: "parse_error",
      srcIp: null, dstIp: null, srcPort: null, dstPort: null, username: null, domain: null,
      process: null, commandLine: null, filePath: null, fileName: null,
      hashMd5: null, hashSha1: null, hashSha256: null,
      url: null, httpMethod: null, statusCode: null, userAgent: null,
      message: "JSON parse failed — ensure input is valid JSON array or NDJSON",
      raw: content.slice(0, 200), normalized: {},
    } satisfies ParsedEvent];
  }

  return (objects as Record<string, unknown>[]).map((obj, i) => {
    const get = (...keys: string[]): unknown => {
      for (const k of keys) {
        // case-insensitive lookup
        const found = Object.keys(obj).find((ok) => ok.toLowerCase() === k.toLowerCase());
        if (found !== undefined && obj[found] !== undefined) return obj[found];
      }
      return null;
    };

    return {
      lineNumber: i + 1,
      timestamp: toDate(get("timestamp", "time", "datetime", "@timestamp", "ts", "TimeCreated")),
      sourceApp: "custom-json",
      eventType: toStr(get("event_type", "eventtype", "type", "action", "category")),
      srcIp:      toStr(get("src_ip", "srcip", "source_ip", "client_ip", "remote_addr")),
      dstIp:      toStr(get("dst_ip", "dstip", "dest_ip", "server_ip")),
      srcPort:    toInt(get("src_port", "srcport", "sport")),
      dstPort:    toInt(get("dst_port", "dstport", "dport", "port")),
      username:   toStr(get("username", "user", "account", "login")),
      domain:     toStr(get("domain", "hostname", "host", "computer")),
      process:    toStr(get("process", "process_name", "ProcessName", "proc")),
      commandLine:toStr(get("command_line", "commandline", "cmd", "CommandLine")),
      filePath:   toStr(get("file_path", "filepath", "path", "FilePath")),
      fileName:   toStr(get("file_name", "filename", "FileName")),
      hashMd5:    toStr(get("md5", "hash_md5", "Hashes.MD5")),
      hashSha1:   toStr(get("sha1", "hash_sha1")),
      hashSha256: toStr(get("sha256", "hash_sha256", "sha2")),
      url:        toStr(get("url", "uri", "request_url")),
      httpMethod: toStr(get("method", "http_method", "verb")),
      statusCode: toInt(get("status", "status_code", "http_status", "StatusCode")),
      userAgent:  toStr(get("user_agent", "useragent", "UserAgent")),
      message:    toStr(get("message", "msg", "description", "log", "event.original")) ?? JSON.stringify(obj).slice(0, 200),
      raw: JSON.stringify(obj),
      normalized: obj,
    } satisfies ParsedEvent;
  });
}
