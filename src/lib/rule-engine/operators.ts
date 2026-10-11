// ─────────────────────────────────────────────────────────────────────────────
// Shared rule-condition operator evaluation.
//
// Extracted out of log-analysis/rule-engine.ts so it can be reused by
// pcap-analysis/rule-engine.ts without either domain depending on the
// other. The field vocabularies (LogField vs. PCAP_FIELDS) and the
// StoredRule/condition-grouping logic stay separate per domain — this is
// the one piece that's genuinely identical between them.
// ─────────────────────────────────────────────────────────────────────────────

export type RuleOperator =
  | "equals"
  | "not_equals"
  | "contains"
  | "not_contains"
  | "starts_with"
  | "ends_with"
  | "regex"
  | "in_list"
  | "greater_than"
  | "less_than";

export function applyOperator(fieldVal: string, operator: RuleOperator, ruleVal: string): boolean {
  const fv = fieldVal.toLowerCase();
  const rv = ruleVal.toLowerCase().trim();

  switch (operator) {
    case "equals":       return fv === rv;
    case "not_equals":   return fv !== rv;
    case "contains":     return fv.includes(rv);
    case "not_contains": return !fv.includes(rv);
    case "starts_with":  return fv.startsWith(rv);
    case "ends_with":    return fv.endsWith(rv);
    case "regex": {
      try { return new RegExp(ruleVal, "i").test(fieldVal); }
      catch { return false; }
    }
    case "in_list": {
      const list = rv.split(",").map((s) => s.trim());
      return list.includes(fv);
    }
    case "greater_than": {
      const n = parseFloat(fieldVal);
      return !isNaN(n) && n > parseFloat(rv);
    }
    case "less_than": {
      const n = parseFloat(fieldVal);
      return !isNaN(n) && n < parseFloat(rv);
    }
    default: return false;
  }
}
