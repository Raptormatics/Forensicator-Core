import type { ParsedEvent } from "../types";

// Syslog / Linux auth.log
// Jun  4 12:30:00 hostname sshd[1234]: Accepted password for john from 10.0.0.1 port 22
// or RFC5424:  <14>1 2026-06-04T12:30:00.000Z hostname sshd - - - message

const TRAD_RE  = /^(\w{3}\s+\d{1,2}\s+[\d:]+)\s+(\S+)\s+([^\[]+?)(?:\[(\d+)\])?:\s+(.+)$/;
const RFC5424  = /^<\d+>1\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(.+)$/;

const IPV4_RE  = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const USER_RE  = /(?:for|user)\s+(\S+)/i;
const PORT_RE  = /port\s+(\d+)/i;
const FAIL_RE  = /fail|invalid|error|reject|disconnect/i;
const SUDO_RE  = /sudo/i;
const SU_RE    = /^\s*su\b/i;

function parseTradDate(raw: string): Date | null {
  try {
    return new Date(`${raw} ${new Date().getFullYear()}`);
  } catch { return null; }
}

export function parseSyslog(content: string): ParsedEvent[] {
  return content.split("\n").filter((l) => l.trim()).map((line, i) => {
    // Try RFC5424 first
    const rfc = line.match(RFC5424);
    if (rfc) {
      const [, ts, host, process, msg] = rfc;
      const ip = msg.match(IPV4_RE)?.[0] ?? null;
      const user = msg.match(USER_RE)?.[1] ?? null;
      return {
        lineNumber: i + 1,
        timestamp: new Date(ts),
        sourceApp: "syslog",
        eventType: FAIL_RE.test(msg) ? "auth_failure" : "syslog",
        srcIp: ip, dstIp: null, srcPort: null, dstPort: null,
        username: user, domain: host ?? null,
        process: process !== "-" ? process : null,
        commandLine: null, filePath: null, fileName: null,
        hashMd5: null, hashSha1: null, hashSha256: null,
        url: null, httpMethod: null, statusCode: null, userAgent: null,
        message: msg,
        raw: line,
        normalized: { ts, host, process, msg },
      } satisfies ParsedEvent;
    }

    // Traditional syslog
    const m = line.match(TRAD_RE);
    if (!m) {
      return {
        lineNumber: i + 1, timestamp: null, sourceApp: "syslog", eventType: "unknown",
        srcIp: null, dstIp: null, srcPort: null, dstPort: null, username: null, domain: null,
        process: null, commandLine: null, filePath: null, fileName: null,
        hashMd5: null, hashSha1: null, hashSha256: null,
        url: null, httpMethod: null, statusCode: null, userAgent: null,
        message: line, raw: line, normalized: { parse_error: true },
      } satisfies ParsedEvent;
    }

    const [, dateStr, host, proc, , msg] = m;
    const ip    = msg.match(IPV4_RE)?.[0] ?? null;
    const user  = msg.match(USER_RE)?.[1] ?? null;
    const port  = msg.match(PORT_RE)?.[1] ? parseInt(msg.match(PORT_RE)![1], 10) : null;
    const isFail = FAIL_RE.test(msg);
    const isSudo = SUDO_RE.test(proc) || SUDO_RE.test(msg);
    const isSu   = SU_RE.test(proc);
    let eventType = "syslog";
    if (isFail) eventType = "auth_failure";
    else if (isSudo || isSu) eventType = "privilege_escalation";

    return {
      lineNumber: i + 1,
      timestamp: parseTradDate(dateStr),
      sourceApp: "syslog",
      eventType,
      srcIp: ip, dstIp: null,
      srcPort: port, dstPort: null,
      username: user, domain: host,
      process: proc.trim(),
      commandLine: null, filePath: null, fileName: null,
      hashMd5: null, hashSha1: null, hashSha256: null,
      url: null, httpMethod: null, statusCode: null, userAgent: null,
      message: msg,
      raw: line,
      normalized: { host, proc: proc.trim(), msg },
    } satisfies ParsedEvent;
  });
}
