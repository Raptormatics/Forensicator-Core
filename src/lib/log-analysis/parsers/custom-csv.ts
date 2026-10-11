import type { ParsedEvent } from "../types";

// Custom CSV log parser with auto-detected delimiter and header row.

function detectDelimiter(line: string): string {
  const candidates = [",", "\t", ";", "|"];
  let best = ",";
  let max  = 0;
  for (const d of candidates) {
    const count = line.split(d).length - 1;
    if (count > max) { max = count; best = d; }
  }
  return best;
}

function parseCsvLine(line: string, delim: string): string[] {
  const result: string[] = [];
  let cur = "", inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { inQuote = !inQuote; continue; }
    if (c === delim && !inQuote) { result.push(cur.trim()); cur = ""; continue; }
    cur += c;
  }
  result.push(cur.trim());
  return result;
}

function toStr(v: string | undefined): string | null {
  if (!v || v.trim() === "" || v.trim() === "-") return null;
  return v.trim();
}
function toInt(v: string | undefined): number | null {
  if (!v) return null;
  const n = parseInt(v, 10);
  return isNaN(n) ? null : n;
}
function toDate(v: string | undefined): Date | null {
  if (!v || !v.trim()) return null;
  try { const d = new Date(v.trim()); return isNaN(d.getTime()) ? null : d; }
  catch { return null; }
}

function headerMatch(headers: string[], candidates: string[]): number {
  for (const c of candidates) {
    const idx = headers.findIndex((h) => h.toLowerCase().trim() === c.toLowerCase());
    if (idx >= 0) return idx;
  }
  return -1;
}

export function parseCustomCsv(content: string): ParsedEvent[] {
  const lines = content.split("\n").filter((l) => l.trim());
  if (lines.length === 0) return [];

  const delim    = detectDelimiter(lines[0]);
  const headers  = parseCsvLine(lines[0], delim).map((h) => h.toLowerCase().replace(/\s+/g, "_"));
  const dataLines = lines.slice(1);

  // Column index helpers
  const col = (...names: string[]) => headerMatch(headers, names);

  const idxTs      = col("timestamp", "datetime", "date_time", "time", "date", "@timestamp");
  const idxEvType  = col("event_type", "eventtype", "type", "action", "category");
  const idxSrcIp   = col("src_ip", "source_ip", "srcip", "client_ip", "remote_addr", "ip");
  const idxDstIp   = col("dst_ip", "dest_ip", "dstip", "server_ip");
  const idxSrcPort = col("src_port", "srcport", "sport");
  const idxDstPort = col("dst_port", "dport", "dstport", "port");
  const idxUser    = col("username", "user", "account", "login");
  const idxDomain  = col("domain", "hostname", "host", "computer");
  const idxProcess = col("process", "process_name", "proc");
  const idxCmd     = col("command_line", "commandline", "cmd");
  const idxFilePath= col("file_path", "filepath", "path");
  const idxFileName= col("file_name", "filename");
  const idxMd5     = col("md5", "hash_md5");
  const idxSha1    = col("sha1", "hash_sha1");
  const idxSha256  = col("sha256", "hash_sha256", "sha2");
  const idxUrl     = col("url", "uri", "request_url");
  const idxMethod  = col("method", "http_method", "verb");
  const idxStatus  = col("status", "status_code", "http_status");
  const idxUa      = col("user_agent", "useragent");
  const idxMsg     = col("message", "msg", "description", "log");

  return dataLines.map((line, i) => {
    const vals = parseCsvLine(line, delim);
    const v = (idx: number) => idx >= 0 ? vals[idx] : undefined;

    // Build normalized key-value map
    const normalized: Record<string, string> = {};
    headers.forEach((h, hi) => { if (vals[hi]) normalized[h] = vals[hi]; });

    return {
      lineNumber: i + 2,
      timestamp:   toDate(v(idxTs)),
      sourceApp:   "custom-csv",
      eventType:   toStr(v(idxEvType)),
      srcIp:       toStr(v(idxSrcIp)),
      dstIp:       toStr(v(idxDstIp)),
      srcPort:     toInt(v(idxSrcPort)),
      dstPort:     toInt(v(idxDstPort)),
      username:    toStr(v(idxUser)),
      domain:      toStr(v(idxDomain)),
      process:     toStr(v(idxProcess)),
      commandLine: toStr(v(idxCmd)),
      filePath:    toStr(v(idxFilePath)),
      fileName:    toStr(v(idxFileName)),
      hashMd5:     toStr(v(idxMd5)),
      hashSha1:    toStr(v(idxSha1)),
      hashSha256:  toStr(v(idxSha256)),
      url:         toStr(v(idxUrl)),
      httpMethod:  toStr(v(idxMethod)),
      statusCode:  toInt(v(idxStatus)),
      userAgent:   toStr(v(idxUa)),
      message:     toStr(v(idxMsg)) ?? vals.filter(Boolean).join(" | ").slice(0, 300),
      raw: line,
      normalized,
    } satisfies ParsedEvent;
  });
}
