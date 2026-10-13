/**
 * Rule engine for Windows Artifact Analysis — mirrors ram-analysis/
 * rule-engine.ts's shape exactly, but the "subject" a rule evaluates
 * against can be any of the five parsed row kinds (Shimcache/Amcache/
 * UserAssist/BAM/Autorun) flattened into one subject shape, discriminated
 * by `kind`/`artifact_type` rather than RAM's process-vs-connection split.
 * Operator evaluation itself is shared — see src/lib/rule-engine/operators.ts.
 */
import { applyOperator } from "@/lib/rule-engine/operators";
import { isIocRuleField, resolveIoc, getIocFieldValue, type IocLookupMap, type IocRuleField } from "@/lib/rule-engine/ioc-lookup";
import type { WinArtifactField, WinArtifactRuleCondition } from "./types";
import type { ShimcacheRow, AmcacheRow, UserAssistRow, BamRow, AutorunRow } from "./registry-engine";

export type WinArtifactSubjectKind = "shimcache" | "amcache" | "userassist" | "bam" | "autorun";

export interface WinArtifactRuleSubject {
  kind: WinArtifactSubjectKind;
  refKey: string;
  path: string | null;
  sha1: string | null;
  runCount: number | null;
  category: string | null;
  valueName: string | null;
  keyPath: string | null;
  sid: string | null;
}

export function buildSubjects(data: {
  shimcache: ShimcacheRow[];
  amcache: AmcacheRow[];
  userAssist: UserAssistRow[];
  bam: BamRow[];
  autoruns: AutorunRow[];
}): WinArtifactRuleSubject[] {
  const subjects: WinArtifactRuleSubject[] = [];

  for (const s of data.shimcache) {
    subjects.push({ kind: "shimcache", refKey: s.path, path: s.path, sha1: null, runCount: null, category: null, valueName: null, keyPath: null, sid: null });
  }
  for (const a of data.amcache) {
    subjects.push({ kind: "amcache", refKey: a.path, path: a.path, sha1: a.sha1, runCount: null, category: null, valueName: null, keyPath: null, sid: null });
  }
  for (const u of data.userAssist) {
    subjects.push({ kind: "userassist", refKey: u.programPath, path: u.programPath, sha1: null, runCount: u.runCount, category: null, valueName: null, keyPath: null, sid: null });
  }
  for (const b of data.bam) {
    subjects.push({ kind: "bam", refKey: b.path, path: b.path, sha1: null, runCount: null, category: null, valueName: null, keyPath: null, sid: b.sid });
  }
  for (const r of data.autoruns) {
    subjects.push({
      kind: "autorun",
      refKey: `${r.keyPath}\\${r.valueName ?? ""}`,
      path: r.valueData,
      sha1: null,
      runCount: null,
      category: r.category,
      valueName: r.valueName,
      keyPath: r.keyPath,
      sid: null,
    });
  }

  return subjects;
}

/** Only sha1 (Amcache) is a plausible threat-intel IOC on a Windows
 * Artifact subject — "path" isn't an IocRecord type (ip/hash/url/domain/
 * email), so ioc_* fields only ever resolve against the hash. */
function iocCandidates(subject: WinArtifactRuleSubject): (string | null)[] {
  return [subject.sha1];
}

function getFieldValue(subject: WinArtifactRuleSubject, field: WinArtifactField, iocMap: IocLookupMap): string {
  if (isIocRuleField(field)) {
    return getIocFieldValue(resolveIoc(iocCandidates(subject), iocMap), field);
  }
  const fieldMap: Record<Exclude<WinArtifactField, IocRuleField>, string | number | null> = {
    artifact_type: subject.kind,
    path:          subject.path,
    sha1:          subject.sha1,
    run_count:     subject.runCount,
    category:      subject.category,
    value_name:    subject.valueName,
    key_path:      subject.keyPath,
    sid:           subject.sid,
  };
  const val = fieldMap[field as Exclude<WinArtifactField, IocRuleField>];
  if (val === null || val === undefined) return "";
  return String(val);
}

function evalCondition(subject: WinArtifactRuleSubject, condition: WinArtifactRuleCondition, iocMap: IocLookupMap): string | null {
  if (!condition.field || !condition.value) return null;
  const fieldVal = getFieldValue(subject, condition.field, iocMap);
  if (!fieldVal) return null;
  const hit = applyOperator(fieldVal, condition.operator, condition.value);
  return hit ? fieldVal : null;
}

export interface WinArtifactRuleMatchResult {
  ruleId: string;
  subject: WinArtifactRuleSubject;
  matchedField: string;
  matchedValue: string;
}

export interface StoredWinArtifactRule {
  id: string;
  name: string;
  description: string | null;
  severity: string;
  logic: string;
  conditions: unknown; // JSON from DB
  enabled: boolean;
  tags: string[];
}

/** Run all enabled rules against every parsed row (as a flattened
 * subject). `iocMap` (see src/lib/rule-engine/ioc-lookup.ts) lets a
 * condition on ioc_known/ioc_reputation/ioc_threat_type/ioc_malware_family
 * check the shared threat-intel database against each subject's sha1 —
 * defaults to an empty map so those fields just evaluate empty when
 * omitted. Returns one result per (rule, subject) match. */
export function runRules(
  rules: StoredWinArtifactRule[],
  subjects: WinArtifactRuleSubject[],
  iocMap: IocLookupMap = new Map()
): WinArtifactRuleMatchResult[] {
  const results: WinArtifactRuleMatchResult[] = [];

  for (const rule of rules) {
    if (!rule.enabled) continue;
    const conditions = (Array.isArray(rule.conditions) ? rule.conditions : []) as WinArtifactRuleCondition[];
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
