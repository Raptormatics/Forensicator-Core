import type { ParsedEvent } from "../types";

// IIS W3C Extended Log Format
// #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken

export function parseIIS(content: string): ParsedEvent[] {
  const lines = content.split("\n").filter((l) => l.trim());
  let headers: string[] = [];
  const events: ParsedEvent[] = [];
  let lineNum = 0;

  for (const line of lines) {
    lineNum++;
    if (line.startsWith("#Fields:")) {
      headers = line.replace("#Fields:", "").trim().split(/\s+/);
      continue;
    }
    if (line.startsWith("#")) continue; // comment line

    if (headers.length === 0) {
      // No header yet — try to detect columns from first data line
      continue;
    }

    const parts = line.trim().split(/\s+/);
    const get = (name: string): string | null => {
      const idx = headers.indexOf(name);
      return idx >= 0 && parts[idx] && parts[idx] !== "-" ? parts[idx] : null;
    };

    const date      = get("date");
    const time      = get("time");
    const sIp       = get("s-ip");
    const method    = get("cs-method");
    const uriStem   = get("cs-uri-stem");
    const uriQuery  = get("cs-uri-query");
    const sPort     = get("s-port");
    const csUser    = get("cs-username");
    const cIp       = get("c-ip");
    const ua        = get("cs(User-Agent)") ?? get("cs-useragent");
    const status    = get("sc-status");
    const timeTaken = get("time-taken");

    const tsStr = date && time ? `${date}T${time}Z` : null;
    const timestamp = tsStr ? (() => { try { return new Date(tsStr); } catch { return null; } })() : null;
    const uri = uriQuery && uriQuery !== "-" ? `${uriStem}?${uriQuery}` : uriStem;

    events.push({
      lineNumber: lineNum,
      timestamp,
      sourceApp: "iis",
      eventType: status && parseInt(status, 10) >= 400 ? "error" : "access",
      srcIp: cIp, dstIp: sIp,
      srcPort: null, dstPort: sPort ? parseInt(sPort, 10) : 80,
      username: csUser, domain: null,
      process: null, commandLine: null, filePath: null, fileName: null,
      hashMd5: null, hashSha1: null, hashSha256: null,
      url: uri ?? null,
      httpMethod: method,
      statusCode: status ? parseInt(status, 10) : null,
      userAgent: ua ? decodeURIComponent(ua.replace(/\+/g, " ")) : null,
      message: `${method ?? "?"} ${uri ?? "/"} → ${status ?? "?"}  (${timeTaken ?? "?"}ms)`,
      raw: line,
      normalized: { date, time, sIp, method, uriStem, uriQuery, sPort, csUser, cIp, ua, status, timeTaken },
    } satisfies ParsedEvent);
  }

  return events;
}
