/**
 * Rule engine for RAM Analysis — mirrors pcap-analysis/rule-engine.ts's
 * shape exactly, but the "subject" a rule evaluates against is a flattened
 * process or network-connection row instead of a conversation/DNS row, and
 * the field vocabulary (RamField) is process/connection-rooted instead of
 * packet-rooted. Operator evaluation itself is shared — see
 * src/lib/rule-engine/operators.ts.
 */
import { applyOperator } from "@/lib/rule-engine/operators";
import { isIocRuleField, resolveIoc, getIocFieldValue, type IocLookupMap, type IocRuleField } from "@/lib/rule-engine/ioc-lookup";
import type { RamField, RamRuleCondition } from "./types";
import type { RamProcessRow, RamConnectionRow } from "./types";

export interface RamRuleSubject {
  kind: "process" | "connection";
  refKey: string; // display/grouping key — "pid:name" or "addr:port"
  pid: number | null;
  ppid: number | null;
  processName: string | null;
  processPath: string | null;
  commandLine: string | null;
  parentName: string | null;
  remoteAddr: string | null;
  remotePort: number | null;
  portLocal: number | null;
  protocol: string | null;
  state: string | null;
}

export function buildSubjects(processes: RamProcessRow[], connections: RamConnectionRow[]): RamRuleSubject[] {
  const nameByPid = new Map<number, string>();
  for (const p of processes) nameByPid.set(p.pid, p.name);

  const subjects: RamRuleSubject[] = [];

  for (const proc of processes) {
    subjects.push({
      kind: "process",
      refKey: `${proc.pid}:${proc.name}`,
      pid: proc.pid,
      ppid: proc.ppid,
      processName: proc.name,
      processPath: proc.path,
      commandLine: proc.commandLine,
      parentName: proc.ppid !== null ? nameByPid.get(proc.ppid) ?? null : null,
      remoteAddr: null,
      remotePort: null,
      portLocal: null,
      protocol: null,
      state: null,
    });
  }

  for (const conn of connections) {
    subjects.push({
      kind: "connection",
      refKey: `${conn.foreignAddr ?? "-"}:${conn.foreignPort ?? "-"}`,
      pid: conn.pid,
      ppid: null,
      processName: conn.processName,
      processPath: null,
      commandLine: null,
      parentName: conn.pid !== null ? nameByPid.get(conn.pid) ?? null : null,
      remoteAddr: conn.foreignAddr,
      remotePort: conn.foreignPort,
      portLocal: conn.localPort,
      protocol: conn.protocol,
      state: conn.state,
    });
  }

  return subjects;
}

/** Only remote_addr is a plausible threat-intel IOC on a RAM subject —
 * process subjects have no IP of their own, so this resolves to nothing
 * for them and ioc_* fields simply evaluate empty. */
function iocCandidates(subject: RamRuleSubject): (string | null)[] {
  return [subject.remoteAddr];
}

function getFieldValue(subject: RamRuleSubject, field: RamField, iocMap: IocLookupMap): string {
  if (isIocRuleField(field)) {
    return getIocFieldValue(resolveIoc(iocCandidates(subject), iocMap), field);
  }
  const fieldMap: Record<Exclude<RamField, IocRuleField>, string | number | null> = {
    pid:          subject.pid,
    ppid:         subject.ppid,
    process_name: subject.processName,
    process_path: subject.processPath,
    command_line: subject.commandLine,
    parent_name:  subject.parentName,
    remote_addr:  subject.remoteAddr,
    remote_port:  subject.remotePort,
    port_local:   subject.portLocal,
    protocol:     subject.protocol,
    state:        subject.state,
  };
  const val = fieldMap[field as Exclude<RamField, IocRuleField>];
  if (val === null || val === undefined) return "";
  return String(val);
}

function evalCondition(subject: RamRuleSubject, condition: RamRuleCondition, iocMap: IocLookupMap): string | null {
  if (!condition.field || !condition.value) return null;
  const fieldVal = getFieldValue(subject, condition.field, iocMap);
  if (!fieldVal) return null;
  const hit = applyOperator(fieldVal, condition.operator, condition.value);
  return hit ? fieldVal : null;
}

export interface RamRuleMatchResult {
  ruleId: string;
  subject: RamRuleSubject;
  matchedField: string;
  matchedValue: string;
}

export interface StoredRamRule {
  id: string;
  name: string;
  description: string | null;
  severity: string;
  logic: string;
  conditions: unknown; // JSON from DB
  enabled: boolean;
  tags: string[];
}

/** Run all enabled rules against every process/connection subject. `iocMap`
 * (see src/lib/rule-engine/ioc-lookup.ts) lets a condition on ioc_known/
 * ioc_reputation/ioc_threat_type/ioc_malware_family check the shared
 * threat-intel database — defaults to an empty map so existing callers
 * that don't pass one still work, those fields just evaluate empty then.
 * Returns one result per (rule, subject) match. */
export function runRules(rules: StoredRamRule[], subjects: RamRuleSubject[], iocMap: IocLookupMap = new Map()): RamRuleMatchResult[] {
  const results: RamRuleMatchResult[] = [];

  for (const rule of rules) {
    if (!rule.enabled) continue;
    const conditions = (Array.isArray(rule.conditions) ? rule.conditions : []) as RamRuleCondition[];
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
