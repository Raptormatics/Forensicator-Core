/**
 * Derives which Volatility-derived dataset(s) a rule's conditions actually
 * inspect, purely from the condition field names — no schema change, no
 * new rule metadata to keep in sync. Field vocabulary confirmed against
 * rule-engine.ts's real getFieldValue() field map.
 */
export type RuleScope = "pslist" | "netscan" | "threat-intel";

export const RULE_SCOPE_LABEL: Record<RuleScope, string> = {
  pslist: "Process List (pslist)",
  netscan: "Network Connections (netscan)",
  "threat-intel": "Threat Intel",
};

const PROCESS_FIELDS = new Set(["pid", "ppid", "process_name", "process_path", "command_line", "parent_name"]);
const CONNECTION_FIELDS = new Set(["remote_addr", "remote_port", "port_local", "protocol", "state"]);

export function deriveRuleScopes(conditions: unknown): RuleScope[] {
  if (!Array.isArray(conditions)) return [];
  const scopes = new Set<RuleScope>();
  for (const c of conditions) {
    const field = c && typeof c === "object" ? (c as { field?: unknown }).field : null;
    if (typeof field !== "string") continue;
    if (PROCESS_FIELDS.has(field)) scopes.add("pslist");
    else if (CONNECTION_FIELDS.has(field)) scopes.add("netscan");
    else if (field.startsWith("ioc_")) scopes.add("threat-intel");
  }
  return [...scopes];
}
