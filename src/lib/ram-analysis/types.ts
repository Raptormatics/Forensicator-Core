// ─────────────────────────────────────────────────────────────────────────────
// Shared types for the RAM Analysis module.
// ─────────────────────────────────────────────────────────────────────────────

import { IOC_FIELD_LABELS, type IocRuleField } from "@/lib/rule-engine/ioc-lookup";

/** OS the memory image was captured from — determines which Volatility3
 * plugin namespace/mapper set the processor uses. Selected by the user at
 * upload time (the collector doesn't bundle OS metadata into a standalone
 * artifact upload). */
export type RamOsType = "windows" | "linux" | "macos";

/** Process-list row (windows.pslist.PsList / linux.pslist.PsList /
 * mac.pslist.PsList), after mapping from raw Volatility3 JSON. */
export interface RamProcessRow {
  pid: number;
  ppid: number | null;
  name: string;
  threads: number | null;
  handles: number | null;
  sessionId: number | null; // Windows only
  owner: string | null;     // Linux/macOS UID as a string; null for Windows (sessionId covers that concept there)
  createTime: Date | null;
  exitTime: Date | null;
  commandLine: string | null; // populated by mergeCmdLine()/mergeLinuxPsaux()/mergeMacPsaux(), not pslist itself
  path: string | null;        // best-effort, parsed from commandLine's first token
}

/** Connection row (windows.netscan.NetScan / linux.sockstat.Sockstat /
 * mac.netstat.Netstat), after mapping. */
export interface RamConnectionRow {
  protocol: string | null;
  localAddr: string | null;
  localPort: number | null;
  foreignAddr: string | null;
  foreignPort: number | null;
  state: string | null;
  pid: number | null;
  processName: string | null;
  created: Date | null;
}

/** Malfind row (windows.malware.malfind.Malfind / linux.malware.malfind.Malfind
 * / mac.malfind.Malfind), after mapping. */
export interface RamMalfindHit {
  pid: number | null;
  process: string | null;
  tag: string | null;         // Windows only (VAD tag) — null for Linux/macOS
  protection: string | null;
  commitCharge: number | null;  // Windows only — null for Linux/macOS
  privateMemory: number | null; // Windows only — null for Linux/macOS
  path: string | null;          // Linux only (VMA file path) — null for Windows/macOS
  // Region address range — Windows' plugin calls these "Start VPN"/"End VPN",
  // Linux/macOS call them "Start"/"End". Stored as hex strings (e.g.
  // "0x7ff6a1230000"), not numbers — addresses can exceed Number's safe
  // integer range.
  startAddress: string | null;
  endAddress: string | null;
  // A small (~64 byte) hex preview of the region's first bytes. Only
  // Linux/macOS's malfind embeds this directly in the same JSONL row (via a
  // Hexdump/HexBytes column) — Windows' plugin exposes hexdump/disasm as
  // renderer objects that don't serialize meaningfully through the -r jsonl
  // output this project's Volatility invocation uses, so Windows previews
  // come from the on-demand dump endpoint instead, not this initial pass.
  previewHex: string | null;
}

/** Extracted subset of windows.info.Info's Variable/Value rows (Windows),
 * or of banners.Banners' raw banner string (Linux/macOS). */
export interface RamInfoSummary {
  osBuild: string | null;
  osArch: string | null;
}

export type RuleSeverity = "critical" | "high" | "medium" | "low" | "info";

/** All normalized field names RAM analysis rules can operate against —
 * mirrors PcapField's role, but rooted in process/connection vocabulary
 * instead of packet/conversation vocabulary. */
export type RamField =
  | "pid"
  | "ppid"
  | "process_name"
  | "process_path"
  | "command_line"
  | "parent_name"
  | "remote_addr"
  | "remote_port"
  | "port_local"
  | "protocol"
  | "state"
  | IocRuleField;

export interface RamRuleCondition {
  id: string;
  field: RamField;
  operator: import("@/lib/rule-engine/operators").RuleOperator;
  value: string;
}

export const FIELD_LABELS: Record<RamField, string> = {
  pid:           "Process ID",
  ppid:          "Parent Process ID",
  process_name:  "Process Name",
  process_path:  "Process Path",
  command_line:  "Command Line",
  parent_name:   "Parent Process Name",
  remote_addr:   "Remote Address",
  remote_port:   "Remote Port",
  port_local:    "Local Port",
  protocol:      "Protocol",
  state:         "Connection State",
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
