/**
 * Single-pass, in-memory aggregation over a stream of PacketFields.
 * Memory use is bounded by the number of DISTINCT flows/DNS names, not the
 * packet count — this is what lets a large capture stream through without
 * buffering every packet.
 */
import type { AggregationResult, ConversationAgg, CredentialHit, DnsQueryAgg, PacketFields } from "./types";

/**
 * v1 is IPv4-only (see types.ts / the module-level plan). Anything that
 * doesn't parse as a dotted-quad IPv4 address (including IPv6) is treated
 * as "skip" here — safer than accidentally aggregating/IOC-upserting a
 * malformed or IPv6 value the rest of this module doesn't handle.
 */
export function isPrivateIp(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return true; // not IPv4-shaped — treat as non-public/skip
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10) return true;                          // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12
  if (a === 192 && b === 168) return true;             // 192.168.0.0/16
  if (a === 127) return true;                          // loopback
  if (a === 169 && b === 254) return true;             // link-local
  if (a === 0) return true;                            // "this network"
  if (a >= 224) return true;                            // multicast/reserved
  return false;
}

function isIPv4(ip: string): boolean {
  return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(ip);
}

/** Sorts the two endpoints so A->B and B->A traffic land in the same row. */
function conversationKey(ipA: string, portA: number | null, ipB: string, portB: number | null): {
  key: string; addrA: string; portA: number | null; addrB: string; portB: number | null; swapped: boolean;
} {
  const left = `${ipA}:${portA ?? 0}`;
  const right = `${ipB}:${portB ?? 0}`;
  const swapped = left > right;
  const [addrA, pA, addrB, pB] = swapped ? [ipB, portB, ipA, portA] : [ipA, portA, ipB, portB];
  return { key: `${addrA}:${pA ?? 0}-${addrB}:${pB ?? 0}`, addrA, portA: pA, addrB, portB: pB, swapped };
}

function updateFirstLast(existing: { firstSeen: Date | null; lastSeen: Date | null }, ts: Date | null) {
  if (!ts) return;
  if (!existing.firstSeen || ts < existing.firstSeen) existing.firstSeen = ts;
  if (!existing.lastSeen || ts > existing.lastSeen) existing.lastSeen = ts;
}

export async function aggregate(stream: AsyncGenerator<PacketFields>): Promise<AggregationResult> {
  const conversations = new Map<string, ConversationAgg>();
  const dnsQueries = new Map<string, DnsQueryAgg>();
  const credentialHits: CredentialHit[] = [];

  let packetCount = 0;
  let byteCount = 0;
  let captureStart: Date | null = null;
  let captureEnd: Date | null = null;

  for await (const pkt of stream) {
    packetCount++;
    if (pkt.frameLen) byteCount += pkt.frameLen;

    const ts = pkt.timeEpoch !== null ? new Date(pkt.timeEpoch * 1000) : null;
    if (ts) {
      if (!captureStart || ts < captureStart) captureStart = ts;
      if (!captureEnd || ts > captureEnd) captureEnd = ts;
    }

    // ── Conversation aggregation (IPv4 TCP/UDP only) ──────────────────────
    if (pkt.ipSrc && pkt.ipDst && isIPv4(pkt.ipSrc) && isIPv4(pkt.ipDst)) {
      const protocol: ConversationAgg["protocol"] =
        pkt.tcpSrcPort !== null || pkt.tcpDstPort !== null ? "tcp" :
        pkt.udpSrcPort !== null || pkt.udpDstPort !== null ? "udp" : "other";

      const srcPort = protocol === "tcp" ? pkt.tcpSrcPort : protocol === "udp" ? pkt.udpSrcPort : null;
      const dstPort = protocol === "tcp" ? pkt.tcpDstPort : protocol === "udp" ? pkt.udpDstPort : null;

      const { key, addrA, portA, addrB, portB, swapped } = conversationKey(pkt.ipSrc, srcPort, pkt.ipDst, dstPort);
      const convKey = `${protocol}|${key}`;

      let conv = conversations.get(convKey);
      if (!conv) {
        conv = {
          protocol, addrA, portA, addrB, portB,
          packetsAtoB: 0, packetsBtoA: 0, bytesAtoB: 0, bytesBtoA: 0,
          firstSeen: null, lastSeen: null, tlsSni: null,
        };
        conversations.set(convKey, conv);
      }

      const len = pkt.frameLen ?? 0;
      // "A->B" means src(this packet) === addrA — swapped tells us whether
      // the original src/dst got flipped when we normalized the key.
      if (!swapped) { conv.packetsAtoB++; conv.bytesAtoB += len; }
      else           { conv.packetsBtoA++; conv.bytesBtoA += len; }
      updateFirstLast(conv, ts);

      if (pkt.tlsSni && !conv.tlsSni) conv.tlsSni = pkt.tlsSni;

      // ── Credential-exposure heuristics (never persist the actual secret) ──
      if (pkt.ftpRequestCommand === "USER" || pkt.ftpRequestCommand === "PASS") {
        credentialHits.push({
          kind: "ftp",
          ip: pkt.ipDst, // the FTP server receiving the command
          detail: `Credentials observed on FTP control channel to ${pkt.ipDst}`,
          timestamp: ts,
        });
      }
      if (pkt.httpAuthorization) {
        credentialHits.push({
          kind: "http",
          ip: pkt.ipDst, // the HTTP server receiving the Authorization header
          detail: `HTTP Authorization header observed on request to ${pkt.httpHost ?? pkt.ipDst}`,
          timestamp: ts,
        });
      }
    }

    // ── DNS query aggregation ──────────────────────────────────────────────
    if (pkt.dnsQryName) {
      let dns = dnsQueries.get(pkt.dnsQryName);
      if (!dns) {
        dns = { queryName: pkt.dnsQryName, queryType: pkt.dnsQryType, responseIps: new Set(), count: 0, firstSeen: null, lastSeen: null };
        dnsQueries.set(pkt.dnsQryName, dns);
      }
      dns.count++;
      if (pkt.dnsA) dns.responseIps.add(pkt.dnsA);
      if (pkt.dnsAaaa) dns.responseIps.add(pkt.dnsAaaa);
      updateFirstLast(dns, ts);
    }
  }

  return { conversations, dnsQueries, credentialHits, packetCount, byteCount, captureStart, captureEnd };
}
