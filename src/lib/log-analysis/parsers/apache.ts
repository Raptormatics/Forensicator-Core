import type { ParsedEvent } from "../types";

// Apache Combined Log Format:
// 192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://referer.example" "Mozilla/5.0"
const COMBINED_RE =
  /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S*)\s+(\S+)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

function parseApacheDate(raw: string): Date | null {
  // "10/Oct/2000:13:55:36 -0700"
  try {
    const months: Record<string, string> = {
      Jan: "01", Feb: "02", Mar: "03", Apr: "04", May: "05", Jun: "06",
      Jul: "07", Aug: "08", Sep: "09", Oct: "10", Nov: "11", Dec: "12",
    };
    // day/Mon/year:HH:MM:SS tz
    const m = raw.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([\+\-]\d{4})/);
    if (!m) return null;
    const [, dd, mon, yyyy, HH, MM, SS, tz] = m;
    const tzFormatted = tz.replace(/(\d{2})(\d{2})$/, "$1:$2");
    return new Date(`${yyyy}-${months[mon]}-${dd}T${HH}:${MM}:${SS}${tzFormatted}`);
  } catch { return null; }
}

export function parseApache(content: string): ParsedEvent[] {
  const lines = content.split("\n").filter((l) => l.trim().length > 0);
  return lines.map((line, i) => {
    const m = line.match(COMBINED_RE);
    if (!m) {
      return {
        lineNumber: i + 1, timestamp: null, sourceApp: "apache", eventType: "unknown",
        srcIp: null, dstIp: null, srcPort: null, dstPort: null, username: null,
        domain: null, process: null, commandLine: null, filePath: null, fileName: null,
        hashMd5: null, hashSha1: null, hashSha256: null, url: null,
        httpMethod: null, statusCode: null, userAgent: null, message: line, raw: line,
        normalized: { parse_error: true },
      } satisfies ParsedEvent;
    }
    const [, srcIp, user, dateStr, method, uri, , statusStr, , referrer, ua] = m;
    const status = parseInt(statusStr, 10);
    return {
      lineNumber: i + 1,
      timestamp: parseApacheDate(dateStr),
      sourceApp: "apache",
      eventType: status >= 400 ? "error" : "access",
      srcIp: srcIp !== "-" ? srcIp : null,
      dstIp: null, srcPort: null, dstPort: 80,
      username: user !== "-" ? user : null,
      domain: null, process: null, commandLine: null,
      filePath: null, fileName: null,
      hashMd5: null, hashSha1: null, hashSha256: null,
      url: uri ?? null,
      httpMethod: method ?? null,
      statusCode: status,
      userAgent: ua ?? null,
      message: `${method} ${uri} → ${status}`,
      raw: line,
      normalized: { srcIp, user, dateStr, method, uri, status, referrer: referrer ?? "", ua: ua ?? "" },
    } satisfies ParsedEvent;
  });
}
