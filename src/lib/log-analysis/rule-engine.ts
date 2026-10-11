import type { ParsedEvent, RuleCondition, LogField } from "./types";
import { applyOperator } from "@/lib/rule-engine/operators";
import { isIocRuleField, resolveIoc, getIocFieldValue, type IocLookupMap, type IocRuleField } from "@/lib/rule-engine/ioc-lookup";

// ─────────────────────────────────────────────────────────────────────────────
// Rule engine — evaluate conditions against a ParsedEvent
// ─────────────────────────────────────────────────────────────────────────────

/** Every event value that could plausibly be a threat-intel IOC — checked
 * in order, first match in the lookup map wins. Deliberately excludes
 * username/process/file path even though the extractor tracks those as
 * LogIoc types too — they aren't enrichable indicator types. */
function iocCandidates(event: ParsedEvent): (string | null)[] {
  return [event.srcIp, event.dstIp, event.domain, event.url, event.hashMd5, event.hashSha1, event.hashSha256];
}

/** Retrieve the raw string value for a field from the event */
function getFieldValue(event: ParsedEvent, field: string, iocMap: IocLookupMap): string {
  if (isIocRuleField(field)) {
    return getIocFieldValue(resolveIoc(iocCandidates(event), iocMap), field);
  }
  const fieldMap: Record<Exclude<LogField, IocRuleField>, string | number | null> = {
    src_ip:       event.srcIp,
    dst_ip:       event.dstIp,
    src_port:     event.srcPort,
    dst_port:     event.dstPort,
    username:     event.username,
    domain:       event.domain,
    process:      event.process,
    command_line: event.commandLine,
    file_path:    event.filePath,
    file_name:    event.fileName,
    hash_md5:     event.hashMd5,
    hash_sha1:    event.hashSha1,
    hash_sha256:  event.hashSha256,
    url:          event.url,
    http_method:  event.httpMethod,
    status_code:  event.statusCode,
    user_agent:   event.userAgent,
    message:      event.message,
    event_type:   event.eventType,
  };

  const val = fieldMap[field as Exclude<LogField, IocRuleField>];
  if (val === null || val === undefined) return "";
  return String(val);
}

/** Returns the matched value string if the condition hits, or null */
function evalCondition(event: ParsedEvent, condition: RuleCondition, iocMap: IocLookupMap): string | null {
  if (!condition.field || !condition.value) return null;
  const fieldVal = getFieldValue(event, condition.field, iocMap);
  if (!fieldVal) return null;
  const hit = applyOperator(fieldVal, condition.operator, condition.value);
  return hit ? fieldVal : null;
}

export interface RuleMatchResult {
  ruleId: string;
  eventLineNumber: number;
  matchedField: string;
  matchedValue: string;
}

export interface StoredRule {
  id: string;
  name: string;
  description: string | null;
  severity: string;
  logic: string;
  conditions: unknown; // JSON from DB
  enabled: boolean;
  tags: string[];
}

/**
 * Run all enabled rules against a list of parsed events. `iocMap` (see
 * src/lib/rule-engine/ioc-lookup.ts) lets a condition on ioc_known/
 * ioc_reputation/ioc_threat_type/ioc_malware_family check the shared
 * threat-intel database — defaults to an empty map so existing callers
 * that don't pass one still work, those fields just evaluate empty then.
 * Returns one result per (rule, event) match.
 */
export function runRules(rules: StoredRule[], events: ParsedEvent[], iocMap: IocLookupMap = new Map()): RuleMatchResult[] {
  const results: RuleMatchResult[] = [];

  for (const rule of rules) {
    if (!rule.enabled) continue;
    const conditions = (Array.isArray(rule.conditions)
      ? rule.conditions
      : []) as RuleCondition[];

    if (conditions.length === 0) continue;
    const logicAND = (rule.logic ?? "AND").toUpperCase() === "AND";

    for (const event of events) {
      const condResults = conditions.map((c) => ({
        condition: c,
        matched: evalCondition(event, c, iocMap),
      }));

      const passed = logicAND
        ? condResults.every((r) => r.matched !== null)
        : condResults.some((r) => r.matched !== null);

      if (passed) {
        // Use the first matched condition's field/value for display
        const firstHit = condResults.find((r) => r.matched !== null);
        results.push({
          ruleId:          rule.id,
          eventLineNumber: event.lineNumber,
          matchedField:    firstHit?.condition.field ?? "",
          matchedValue:    firstHit?.matched ?? "",
        });
      }
    }
  }

  return results;
}
