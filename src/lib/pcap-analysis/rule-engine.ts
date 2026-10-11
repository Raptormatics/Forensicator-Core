/**
 * Rule engine for PCAP Analysis — mirrors log-analysis/rule-engine.ts's
 * shape exactly, but the "subject" a rule evaluates against is a flattened
 * conversation or DNS-query row instead of a ParsedEvent, and the field
 * vocabulary (PcapField) is conversation/DNS-rooted instead of log-line-
 * rooted. Operator evaluation itself is shared — see
 * src/lib/rule-engine/operators.ts.
 */
import { applyOperator } from "@/lib/rule-engine/operators";
import { isIocRuleField, resolveIoc, getIocFieldValue, type IocLookupMap, type IocRuleField } from "@/lib/rule-engine/ioc-lookup";
import type { AggregationResult, PcapField, PcapRuleCondition } from "./types";

export interface PcapRuleSubject {
  kind: "conversation" | "dns";
  refKey: string; // display/grouping key — "addrA:portA <-> addrB:portB" or the DNS query name
  addrA: string | null;
  addrB: string | null;
  portA: number | null;
  portB: number | null;
  protocol: string | null;
  packetsTotal: number | null;
  bytesTotal: number | null;
  dnsQuery: string | null;
  tlsSni: string | null;
  firstSeen: Date | null;
  lastSeen: Date | null;
}

export function buildSubjects(result: AggregationResult): PcapRuleSubject[] {
  const subjects: PcapRuleSubject[] = [];

  for (const conv of result.conversations.values()) {
    subjects.push({
      kind: "conversation",
      refKey: `${conv.addrA}:${conv.portA ?? "-"} <-> ${conv.addrB}:${conv.portB ?? "-"}`,
      addrA: conv.addrA,
      addrB: conv.addrB,
      portA: conv.portA,
      portB: conv.portB,
      protocol: conv.protocol,
      packetsTotal: conv.packetsAtoB + conv.packetsBtoA,
      bytesTotal: conv.bytesAtoB + conv.bytesBtoA,
      dnsQuery: null,
      tlsSni: conv.tlsSni,
      firstSeen: conv.firstSeen,
      lastSeen: conv.lastSeen,
    });
  }

  for (const dns of result.dnsQueries.values()) {
    subjects.push({
      kind: "dns",
      refKey: dns.queryName,
      addrA: null, addrB: null, portA: null, portB: null, protocol: null,
      packetsTotal: dns.count,
      bytesTotal: null,
      dnsQuery: dns.queryName,
      tlsSni: null,
      firstSeen: dns.firstSeen,
      lastSeen: dns.lastSeen,
    });
  }

  return subjects;
}

/** Every value on a subject that could plausibly be a threat-intel IOC —
 * checked in order, first match in the lookup map wins (same "any
 * indicator on this subject is known-bad" semantic the built-in "Known
 * IOC observed" heuristic already uses). */
function iocCandidates(subject: PcapRuleSubject): (string | null)[] {
  return [subject.addrA, subject.addrB, subject.dnsQuery, subject.tlsSni];
}

function getFieldValue(subject: PcapRuleSubject, field: PcapField, iocMap: IocLookupMap): string {
  if (isIocRuleField(field)) {
    return getIocFieldValue(resolveIoc(iocCandidates(subject), iocMap), field);
  }
  const fieldMap: Record<Exclude<PcapField, IocRuleField>, string | number | null> = {
    addr_a:        subject.addrA,
    addr_b:        subject.addrB,
    port_a:        subject.portA,
    port_b:        subject.portB,
    protocol:      subject.protocol,
    packets_total: subject.packetsTotal,
    bytes_total:   subject.bytesTotal,
    dns_query:     subject.dnsQuery,
    tls_sni:       subject.tlsSni,
  };
  const val = fieldMap[field as Exclude<PcapField, IocRuleField>];
  if (val === null || val === undefined) return "";
  return String(val);
}

function evalCondition(subject: PcapRuleSubject, condition: PcapRuleCondition, iocMap: IocLookupMap): string | null {
  if (!condition.field || !condition.value) return null;
  const fieldVal = getFieldValue(subject, condition.field, iocMap);
  if (!fieldVal) return null;
  const hit = applyOperator(fieldVal, condition.operator, condition.value);
  return hit ? fieldVal : null;
}

export interface PcapRuleMatchResult {
  ruleId: string;
  subject: PcapRuleSubject;
  matchedField: string;
  matchedValue: string;
}

export interface StoredPcapRule {
  id: string;
  name: string;
  description: string | null;
  severity: string;
  logic: string;
  conditions: unknown; // JSON from DB
  enabled: boolean;
  tags: string[];
}

/** Run all enabled rules against every conversation/DNS subject. `iocMap`
 * (see src/lib/rule-engine/ioc-lookup.ts) lets a condition on ioc_known/
 * ioc_reputation/ioc_threat_type/ioc_malware_family check the shared
 * threat-intel database, not just this capture's own raw values — defaults
 * to an empty map so existing callers/tests that don't pass one still work,
 * those fields just always evaluate empty in that case. Returns one result
 * per (rule, subject) match. */
export function runRules(rules: StoredPcapRule[], subjects: PcapRuleSubject[], iocMap: IocLookupMap = new Map()): PcapRuleMatchResult[] {
  const results: PcapRuleMatchResult[] = [];

  for (const rule of rules) {
    if (!rule.enabled) continue;
    const conditions = (Array.isArray(rule.conditions) ? rule.conditions : []) as PcapRuleCondition[];
    if (conditions.length === 0) continue;
    const logicAND = (rule.logic ?? "AND").toUpperCase() === "AND";

    for (const subject of subjects) {
      const condResults = conditions.map((c) => ({ condition: c, matched: evalCondition(subject, c, iocMap) }));
      const passed = logicAND
        ? condResults.every((r) => r.matched !== null)
        : condResults.some((r) => r.matched !== null);

      if (passed) {
        const firstHit = condResults.find((r) => r.matched !== null);
        results.push({
          ruleId: rule.id,
          subject,
          matchedField: firstHit?.condition.field ?? "",
          matchedValue: firstHit?.matched ?? "",
        });
      }
    }
  }

  return results;
}
