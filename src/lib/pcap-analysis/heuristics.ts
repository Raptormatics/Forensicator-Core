/**
 * Built-in v1 detections — plain functions over the aggregated result, not
 * user-editable rules (PcapAnalysisRule is a separate, later layer on top
 * of the same data). Each returns zero or more PcapFinding-shaped rows
 * with ruleId left for the caller to set to null.
 */
import { isPrivateIp } from "./aggregator";
import type { AggregationResult } from "./types";

export interface HeuristicFinding {
  title: string;
  description: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  matchCount: number;
  firstSeen: Date | null;
  lastSeen: Date | null;
  matchedField: string | null;
  matchedValue: string | null;
}

// Ports commonly associated with high-risk/legacy services when reached
// from outside — not exhaustive, just a small, deliberately conservative
// v1 watch-list. Anything more elaborate belongs in PcapAnalysisRule.
const WATCHED_PORTS: Record<number, string> = {
  23:   "Telnet (cleartext remote shell)",
  3389: "RDP",
  4444: "Common reverse-shell/Metasploit default port",
  1080: "SOCKS proxy",
  6667: "IRC (common C2 channel)",
};

const HIGH_VOLUME_BYTES_THRESHOLD = 100 * 1024 * 1024; // 100MB

/** Detection 1 — a conversation reaches a public address on a watched port. */
function detectWatchedPorts(result: AggregationResult): HeuristicFinding[] {
  const findings: HeuristicFinding[] = [];
  for (const conv of result.conversations.values()) {
    const candidates = [
      { port: conv.portA, ip: conv.addrA },
      { port: conv.portB, ip: conv.addrB },
    ];
    for (const { port, ip } of candidates) {
      if (port === null || !(port in WATCHED_PORTS)) continue;
      if (isPrivateIp(ip)) continue;
      findings.push({
        title: `Traffic to unusual/high-risk port ${port} (${WATCHED_PORTS[port]})`,
        description: `Conversation between ${conv.addrA}:${conv.portA ?? "-"} and ${conv.addrB}:${conv.portB ?? "-"} used port ${port}, associated with ${WATCHED_PORTS[port]}.`,
        severity: "medium",
        matchCount: conv.packetsAtoB + conv.packetsBtoA,
        firstSeen: conv.firstSeen,
        lastSeen: conv.lastSeen,
        matchedField: "port",
        matchedValue: String(port),
      });
    }
  }
  return findings;
}

/**
 * Detection 2 — cleartext-credential protocol observed. SECURITY: never
 * includes the actual username/password/Authorization header value —
 * result.credentialHits' `detail` strings are already scrubbed of secrets
 * at aggregation time (see aggregator.ts), this just groups them.
 */
function detectCleartextCredentials(result: AggregationResult): HeuristicFinding[] {
  if (result.credentialHits.length === 0) return [];

  const byIp = new Map<string, { kind: string; detail: string; count: number; first: Date | null; last: Date | null }>();
  for (const hit of result.credentialHits) {
    const existing = byIp.get(hit.ip);
    if (existing) {
      existing.count++;
      if (hit.timestamp && (!existing.first || hit.timestamp < existing.first)) existing.first = hit.timestamp;
      if (hit.timestamp && (!existing.last || hit.timestamp > existing.last)) existing.last = hit.timestamp;
    } else {
      byIp.set(hit.ip, { kind: hit.kind, detail: hit.detail, count: 1, first: hit.timestamp, last: hit.timestamp });
    }
  }

  return Array.from(byIp.entries()).map(([ip, agg]) => ({
    title: "Cleartext credentials observed",
    description: agg.detail,
    severity: "high" as const,
    matchCount: agg.count,
    firstSeen: agg.first,
    lastSeen: agg.last,
    matchedField: "destination_ip",
    matchedValue: ip,
  }));
}

/** Detection 3 — high-volume single-destination transfer (possible exfil/bulk transfer). */
function detectHighVolumeTransfers(result: AggregationResult): HeuristicFinding[] {
  const findings: HeuristicFinding[] = [];
  for (const conv of result.conversations.values()) {
    const total = conv.bytesAtoB + conv.bytesBtoA;
    if (total < HIGH_VOLUME_BYTES_THRESHOLD) continue;
    // Only flag when at least one side is a public address — bulk transfer
    // between two private hosts (e.g. internal backups) is expected noise.
    if (isPrivateIp(conv.addrA) && isPrivateIp(conv.addrB)) continue;

    findings.push({
      title: "High-volume single-destination transfer",
      description: `${(total / (1024 * 1024)).toFixed(1)}MB transferred between ${conv.addrA} and ${conv.addrB} — possible bulk transfer or exfiltration.`,
      severity: "medium",
      matchCount: conv.packetsAtoB + conv.packetsBtoA,
      firstSeen: conv.firstSeen,
      lastSeen: conv.lastSeen,
      matchedField: "bytes_total",
      matchedValue: String(total),
    });
  }
  return findings;
}

export function runHeuristics(result: AggregationResult): HeuristicFinding[] {
  return [
    ...detectWatchedPorts(result),
    ...detectCleartextCredentials(result),
    ...detectHighVolumeTransfers(result),
  ];
}
