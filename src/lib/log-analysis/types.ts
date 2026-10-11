// ─────────────────────────────────────────────────────────────────────────────
// Shared types for the Log Analysis module
// ─────────────────────────────────────────────────────────────────────────────

// Operator evaluation is shared with pcap-analysis — see src/lib/rule-engine/operators.ts.
import type { RuleOperator } from "@/lib/rule-engine/operators";
export type { RuleOperator };
import { IOC_FIELD_LABELS, type IocRuleField } from "@/lib/rule-engine/ioc-lookup";

/** All IOC / normalized field names rules can operate against */
export type LogField =
  | "src_ip"
  | "dst_ip"
  | "src_port"
  | "dst_port"
  | "username"
  | "domain"
  | "process"
  | "command_line"
  | "file_path"
  | "file_name"
  | "hash_md5"
  | "hash_sha1"
  | "hash_sha256"
  | "url"
  | "http_method"
  | "status_code"
  | "user_agent"
  | "message"
  | "event_type"
  | IocRuleField;

export type RuleSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface RuleCondition {
  id: string;
  field: LogField;
  operator: RuleOperator;
  value: string;
}

export interface LogAnalysisRuleInput {
  name: string;
  description?: string;
  severity: RuleSeverity;
  enabled: boolean;
  logic: "AND" | "OR";
  conditions: RuleCondition[];
  tags: string[];
}

/** A single normalized event row (before DB storage) */
export interface ParsedEvent {
  lineNumber: number;
  timestamp: Date | null;
  sourceApp: string;
  eventType: string | null;

  srcIp: string | null;
  dstIp: string | null;
  srcPort: number | null;
  dstPort: number | null;
  username: string | null;
  domain: string | null;
  process: string | null;
  commandLine: string | null;
  filePath: string | null;
  fileName: string | null;
  hashMd5: string | null;
  hashSha1: string | null;
  hashSha256: string | null;
  url: string | null;
  httpMethod: string | null;
  statusCode: number | null;
  userAgent: string | null;
  message: string | null;

  raw: string;
  /** Full structured fields as parsed by the source parser */
  normalized: Record<string, unknown>;
}

/** IOC hit: deduplicated type+value pairs */
export interface IocHit {
  type: string;
  value: string;
}

export const SOURCE_TYPES = [
  { id: "apache",        label: "Apache HTTP Server",      description: "Combined / common access & error logs",    icon: "🌐" },
  { id: "nginx",         label: "Nginx",                   description: "Nginx access & error logs",                icon: "⚡" },
  { id: "syslog",        label: "Syslog / Linux Auth",     description: "Generic syslog, auth.log, kern.log",       icon: "🐧" },
  { id: "windows-event", label: "Windows Event Log",       description: "CSV / JSON export from Event Viewer",      icon: "🪟" },
  { id: "iis",           label: "IIS (Microsoft)",         description: "IIS W3C Extended log format",              icon: "🏢" },
  { id: "firewall",      label: "Firewall / Generic",      description: "Palo Alto, Fortinet, pfSense key=value",   icon: "🛡️" },
  { id: "custom-json",   label: "Custom JSON / NDJSON",    description: "Line-delimited or array JSON logs",        icon: "{ }" },
  { id: "custom-csv",    label: "Custom CSV",              description: "Delimited text with header row",           icon: "📋" },
  { id: "nginx-ingress", label: "Nginx Ingress Controller", description: "Kubernetes Nginx Ingress klog error logs", icon: "☸️" },
  { id: "postgresql",    label: "PostgreSQL",              description: "PostgreSQL pg_stat_database JSON rows",    icon: "🐘" },
] as const;

export type SourceTypeId = typeof SOURCE_TYPES[number]["id"];

export const FIELD_LABELS: Record<LogField, string> = {
  src_ip:       "Source IP",
  dst_ip:       "Destination IP",
  src_port:     "Source Port",
  dst_port:     "Destination Port",
  username:     "Username",
  domain:       "Domain",
  process:      "Process Name",
  command_line: "Command Line",
  file_path:    "File Path",
  file_name:    "File Name",
  hash_md5:     "Hash (MD5)",
  hash_sha1:    "Hash (SHA1)",
  hash_sha256:  "Hash (SHA256)",
  url:          "URL",
  http_method:  "HTTP Method",
  status_code:  "HTTP Status Code",
  user_agent:   "User-Agent",
  message:      "Log Message",
  event_type:   "Event Type",
  ...IOC_FIELD_LABELS,
};

export const OPERATORS: { value: RuleOperator; label: string }[] = [
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
