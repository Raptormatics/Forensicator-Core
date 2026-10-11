import type { ParsedEvent } from "../types";

// Generic key=value firewall log parser (Palo Alto, Fortinet, pfSense, Check Point, etc.)
// Lines like:  2026-06-04T12:00:00 logtype=TRAFFIC srcip=1.2.3.4 dstip=5.6.7.8 ...

const TS_PREFIX = /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s*/;
const KV_RE     = /(\w+)=(?:"([^"]*?)"|(\S+))/g;

export function parseFirewall(content: string): ParsedEvent[] {
  return content.split("\n").filter((l) => l.trim()).map((line, i) => {
    const tsMatch = line.match(TS_PREFIX);
    const tsRaw   = tsMatch?.[1] ?? null;
    const rest    = tsRaw ? line.slice(tsMatch![0].length) : line;

    const kv: Record<string, string> = {};
    let m: RegExpExecArray | null;
    KV_RE.lastIndex = 0;
    while ((m = KV_RE.exec(rest)) !== null) {
      kv[m[1].toLowerCase()] = (m[2] ?? m[3]).trim();
    }

    const get = (...keys: string[]): string | null => {
      for (const k of keys) if (kv[k] && kv[k] !== "-") return kv[k];
      return null;
    };

    const ts = tsRaw ? (() => { try { return new Date(tsRaw.replace(" ", "T")); } catch { return null; } })() : null;
    const srcIp    = get("srcip", "src_ip", "src", "sip");
    const dstIp    = get("dstip", "dst_ip", "dst", "dip");
    const srcPort  = get("srcport", "sport") ? parseInt(get("srcport", "sport")!, 10) : null;
    const dstPort  = get("dstport", "dport") ? parseInt(get("dstport", "dport")!, 10) : null;
    const user     = get("srcuser", "username", "user", "uname");
    const action   = get("action", "disposition", "verdict");
    const proto    = get("proto", "protocol");
    const app      = get("app", "appid", "application");
    const policy   = get("policyname", "policy", "rule");
    const logtype  = get("logtype", "type", "subtype");

    return {
      lineNumber: i + 1,
      timestamp: ts,
      sourceApp: "firewall",
      eventType: logtype ?? action ?? "traffic",
      srcIp, dstIp, srcPort, dstPort,
      username: user, domain: null,
      process: app ?? null,
      commandLine: null, filePath: null, fileName: null,
      hashMd5: null, hashSha1: null, hashSha256: null,
      url: get("url", "uri") ?? null,
      httpMethod: get("method") ?? null,
      statusCode: null, userAgent: null,
      message: [action, proto, app, policy].filter(Boolean).join(" / ") || line.slice(0, 100),
      raw: line,
      normalized: kv,
    } satisfies ParsedEvent;
  });
}
