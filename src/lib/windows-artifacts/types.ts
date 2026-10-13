// ─────────────────────────────────────────────────────────────────────────────
// Shared types for Windows Artifact Analysis.
// ─────────────────────────────────────────────────────────────────────────────

import { IOC_FIELD_LABELS, type IocRuleField } from "@/lib/rule-engine/ioc-lookup";

export type RuleSeverity = "critical" | "high" | "medium" | "low" | "info";

/** Which uploaded file role a hive/artifact was parsed from — matches
 * WindowsArtifactFile.role in the Prisma schema. */
export type WinArtifactFileRole =
  | "system_hive"
  | "software_hive"
  | "security_hive"
  | "ntuser_hive"
  | "amcache_hive"
  | "usrclass_hive";

/** All normalized field names Windows Artifact rules can operate against —
 * mirrors RamField/PcapField's role, rooted in the heterogeneous
 * Shimcache/Amcache/UserAssist/BAM/Autoruns vocabulary instead of a single
 * row shape, since one WindowsArtifactFile can yield several different
 * kinds of subject. */
export type WinArtifactField =
  | "artifact_type" // shimcache | amcache | userassist | bam | autorun
  | "path"
  | "sha1"
  | "run_count"
  | "category"
  | "value_name"
  | "key_path"
  | "sid"
  | IocRuleField;

export interface WinArtifactRuleCondition {
  id: string;
  field: WinArtifactField;
  operator: import("@/lib/rule-engine/operators").RuleOperator;
  value: string;
}

export const FIELD_LABELS: Record<WinArtifactField, string> = {
  artifact_type: "Artifact Type",
  path:          "Path",
  sha1:          "SHA1",
  run_count:     "Run Count",
  category:      "Autorun Category",
  value_name:    "Registry Value Name",
  key_path:      "Registry Key Path",
  sid:           "User SID",
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
