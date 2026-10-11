import type { ParsedEvent } from "../types";

// Nginx default log format:
// $remote_addr - $remote_user [$time_local] "$request" $status $bytes_sent "$http_referer" "$http_user_agent"
const NGINX_RE =
  /^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S*)\s+(\S+)"\s+(\d{3})\s+(\d+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

function parseNginxDate(raw: string): Date | null {
  try {
    // "04/Jun/2026:12:30:00 +0000"
    const months: Record<string, string> = {
      Jan: "01", Feb: "02", Mar: "03", Apr: "04", May: "05", Jun: "06",
      Jul: "07", Aug: "08", Sep: "09", Oct: "10", Nov: "11", Dec: "12",
    };
    const m = raw.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([\+\-]\d{4})/);
    if (!m) return null;
    const [, dd, mon, yyyy, HH, MM, SS, tz] = m;
    const tzF = tz.replace(/(\d{2})(\d{2})$/, "$1:$2");
    return new Date(`${yyyy}-${months[mon]}-${dd}T${HH}:${MM}:${SS}${tzF}`);
  } catch { return null; }
}

export function parseNginx(content: string): ParsedEvent[] {
  return content.split("\n").filter((l) => l.trim()).map((line, i) => {
    const m = line.match(NGINX_RE);
    if (!m) {
      return {
        lineNumber: i + 1, timestamp: null, sourceApp: "nginx", eventType: "unknown",
        srcIp: null, dstIp: null, srcPort: null, dstPort: null, username: null, domain: null,
        process: null, commandLine: null, filePath: null, fileName: null,
        hashMd5: null, hashSha1: null, hashSha256: null, url: null,
        httpMethod: null, statusCode: null, userAgent: null, message: line, raw: line,
        normalized: { parse_error: true },
      } satisfies ParsedEvent;
    }
    const [, srcIp, user, dateStr, method, uri, , statusStr, , , ua] = m;
    const status = parseInt(statusStr, 10);
    return {
      lineNumber: i + 1,
      timestamp: parseNginxDate(dateStr),
      sourceApp: "nginx",
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
      normalized: { srcIp, user, method, uri, status, ua: ua ?? "" },
    } satisfies ParsedEvent;
  });
}
