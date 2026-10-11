// ─────────────────────────────────────────────────────────────────────────────
// Shared types for the PCAP Analysis module.
// ─────────────────────────────────────────────────────────────────────────────

import { IOC_FIELD_LABELS, type IocRuleField } from "@/lib/rule-engine/ioc-lookup";

/** One line of `tshark -T fields` output, one per packet. Raw strings —
 * tshark leaves a field empty (not present) rather than omitting the
 * column, so every packet line has the same number of tab-separated
 * values in the same order as FIELD_LIST in tshark.ts. */
export interface PacketFields {
  timeEpoch: number | null;
  frameLen: number | null;
  ipSrc: string | null;
  ipDst: string | null;
  ipProto: string | null;
  tcpSrcPort: number | null;
  tcpDstPort: number | null;
  udpSrcPort: number | null;
  udpDstPort: number | null;
  dnsQryName: string | null;
  dnsQryType: string | null;
  dnsA: string | null;
  dnsAaaa: string | null;
  tlsSni: string | null;
  httpHost: string | null;
  httpAuthorization: string | null;
  ftpRequestCommand: string | null;
  ftpRequestArg: string | null;
}

export interface ConversationAgg {
  protocol: "tcp" | "udp" | "other";
  addrA: string;
  portA: number | null;
  addrB: string;
  portB: number | null;
  packetsAtoB: number;
  packetsBtoA: number;
  bytesAtoB: number;
  bytesBtoA: number;
  firstSeen: Date | null;
  lastSeen: Date | null;
  tlsSni: string | null;
}

export interface DnsQueryAgg {
  queryName: string;
  queryType: string | null;
  responseIps: Set<string>;
  count: number;
  firstSeen: Date | null;
  lastSeen: Date | null;
}

export interface CredentialHit {
  kind: "ftp" | "http";
  ip: string;
  detail: string; // safe, non-secret description — never the raw credential
  timestamp: Date | null;
}

export interface AggregationResult {
  conversations: Map<string, ConversationAgg>;
  dnsQueries: Map<string, DnsQueryAgg>;
  credentialHits: CredentialHit[];
  packetCount: number;
  byteCount: number;
  captureStart: Date | null;
  captureEnd: Date | null;
}

/** All normalized field names PCAP analysis rules can operate against —
 * mirrors LogField's role in log-analysis/types.ts, but rooted in
 * conversation/DNS vocabulary instead of log-line vocabulary. */
export type PcapField =
  | "addr_a"
  | "addr_b"
  | "port_a"
  | "port_b"
  | "protocol"
  | "packets_total"
  | "bytes_total"
  | "dns_query"
  | "tls_sni"
  | IocRuleField;

export interface PcapRuleCondition {
  id: string;
  field: PcapField;
  operator: import("@/lib/rule-engine/operators").RuleOperator;
  value: string;
}

export type RuleSeverity = "critical" | "high" | "medium" | "low" | "info";

export const FIELD_LABELS: Record<PcapField, string> = {
  addr_a:        "Endpoint A Address",
  addr_b:        "Endpoint B Address",
  port_a:        "Endpoint A Port",
  port_b:        "Endpoint B Port",
  protocol:      "Protocol",
  packets_total: "Total Packets",
  bytes_total:   "Total Bytes",
  dns_query:     "DNS Query Name",
  tls_sni:       "TLS SNI",
  ...IOC_FIELD_LABELS,
};

export const OPERATORS: { value: import("@/lib/rule-engine/operators").RuleOperator; label: string }[] = [
  { value: "equals",       label: "equals" },
  { value: "not_equals",   label: "not equals" },
  { value: "contains",     label: "contains" },
  { value: "not_contains", label: "does not contain" },
  { value: "starts_with",  label: "starts with" },
  { value: "ends_with",    label: "ends with" },
  { value: "regex",        label: "matches regex" },
  { value: "in_list",      label: "is in list" },
  { value: "greater_than", label: "greater than" },
  { value: "less_than",    label: "less than" },
];

export const SEVERITY_OPTIONS: { value: RuleSeverity; label: string; color: string }[] = [
  { value: "critical", label: "Critical", color: "text-red-400" },
  { value: "high",     label: "High",     color: "text-orange-400" },
  { value: "medium",   label: "Medium",   color: "text-yellow-400" },
  { value: "low",      label: "Low",      color: "text-blue-400" },
  { value: "info",     label: "Info",     color: "text-zinc-400" },
];
