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
  | "usrclass_hive"
  | "prefetch"
  | "lnk"
  | "jumplist_automatic"
  | "jumplist_custom"
  | "mft"
  | "usnjrnl"
  | "srum_db"
  | "wer_report"
  | "wer_dump"
  | "recycle_bin"
  | "notification_db"
  | "search_edb"
  | "quarantine_entry"
  | "quarantine_resource"
  | "bits_queue"
  | "timeline_db";

/** All normalized field names Windows Artifact rules can operate against —
 * mirrors RamField/PcapField's role, rooted in the heterogeneous
 * Shimcache/Amcache/UserAssist/BAM/Autoruns vocabulary instead of a single
 * row shape, since one WindowsArtifactFile can yield several different
 * kinds of subject. */
export type WinArtifactField =
  | "artifact_type" // shimcache | amcache | userassist | bam | autorun | prefetch | prefetch_reference | lnk | jumplist | shellbag | mft | usnjrnl | srum | wer | wer_dump | recyclebin | bits | quarantine_payload | timeline
  | "path"
  | "sha1"
  | "run_count"
  | "category"
  | "value_name"
  | "key_path"
  | "sid"
  | "is_allocated"      // mft only — "true" | "false"
  | "has_timestomp"     // mft only — "true" when creationTime is later than entryModificationTime
  | "usn_reason"         // usnjrnl only — space-joined decoded USN_REASON_* flags
  | "provider_label"    // srum only
  | "exception_code"    // wer | wer_dump only
  | "is_carved"         // bits only — "true" when the job was recovered via carving, not clean parsing
  | "sha256"            // quarantine_payload only
  | IocRuleField;

export interface WinArtifactRuleCondition {
  id: string;
  field: WinArtifactField;
  operator: import("@/lib/rule-engine/operators").RuleOperator;
  value: string;
}

export const FIELD_LABELS: Record<WinArtifactField, string> = {
  artifact_type:  "Artifact Type",
  path:           "Path",
  sha1:           "SHA1",
  run_count:      "Run Count",
  category:       "Autorun Category",
  value_name:     "Registry Value Name",
  key_path:       "Registry Key Path",
  sid:            "User SID",
  is_allocated:   "MFT Entry Allocated",
  has_timestomp:  "Possible Timestomping",
  usn_reason:     "USN Reason Flags",
  provider_label: "SRUM Provider",
  exception_code: "Exception Code",
  is_carved:      "Recovered via Carving",
  sha256:         "SHA256",
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
