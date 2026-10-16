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
import type { ShimcacheRow, AmcacheRow, UserAssistRow, BamRow, AutorunRow, ShellbagRow } from "./registry-engine";
import type { PrefetchEntryRow } from "./prefetch-engine";
import type { LnkEntryRow } from "./lnk-engine";
import type { JumpListEntryRow } from "./jumplist-engine";
import type { MftEntryRow } from "./mft-engine";
import type { UsnJrnlEntryRow } from "./usnjrnl-engine";
import type { SrumEntryRow } from "./srum-engine";
import type { WerReportRow } from "./wer-engine";
import type { WerDumpRow } from "./wer-dump-engine";
import type { RecycleBinRow } from "./recyclebin-engine";
import type { BitsJobRow } from "./bits-engine";
import type { QuarantinePayloadRow } from "./defender-quarantine-engine";
import type { TimelineEntryRow } from "./timeline-engine";

export type WinArtifactSubjectKind = "shimcache" | "amcache" | "userassist" | "bam" | "autorun" | "prefetch" | "prefetch_reference" | "lnk" | "jumplist" | "shellbag" | "mft" | "usnjrnl" | "srum" | "wer" | "wer_dump_module" | "recyclebin" | "bits" | "quarantine_payload" | "timeline";

export interface WinArtifactRuleSubject {
  kind: WinArtifactSubjectKind;
  refKey: string;
  path: string | null;
  sha1: string | null;
  sha256: string | null;
  runCount: number | null;
  category: string | null;
  valueName: string | null;
  keyPath: string | null;
  sid: string | null;
  isAllocated: boolean | null;
  hasTimestomp: boolean | null;
  usnReason: string | null;
  providerLabel: string | null;
  exceptionCode: string | null;
  isCarved: boolean | null;
}

// Every field a specific subject kind doesn't use stays at this default
// (null) — spread this first, then override only the fields that kind
// actually has, rather than repeating all ~15 nulls at every call site.
const BLANK_SUBJECT_FIELDS: Omit<WinArtifactRuleSubject, "kind" | "refKey"> = {
  path: null, sha1: null, sha256: null, runCount: null, category: null, valueName: null, keyPath: null, sid: null,
  isAllocated: null, hasTimestomp: null, usnReason: null, providerLabel: null, exceptionCode: null, isCarved: null,
};

export function buildSubjects(data: {
  shimcache: ShimcacheRow[];
  amcache: AmcacheRow[];
  userAssist: UserAssistRow[];
  bam: BamRow[];
  autoruns: AutorunRow[];
  prefetch?: PrefetchEntryRow[];
  lnk?: LnkEntryRow[];
  jumplist?: JumpListEntryRow[];
  shellbag?: ShellbagRow[];
  mft?: MftEntryRow[];
  usnjrnl?: UsnJrnlEntryRow[];
  srum?: SrumEntryRow[];
  wer?: WerReportRow[];
  werDump?: WerDumpRow[];
  recyclebin?: RecycleBinRow[];
  bits?: BitsJobRow[];
  quarantinePayload?: QuarantinePayloadRow[];
  timeline?: TimelineEntryRow[];
}): WinArtifactRuleSubject[] {
  const subjects: WinArtifactRuleSubject[] = [];

  for (const s of data.shimcache) {
    subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "shimcache", refKey: s.path, path: s.path });
  }
  for (const a of data.amcache) {
    subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "amcache", refKey: a.path, path: a.path, sha1: a.sha1 });
  }
  for (const u of data.userAssist) {
    subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "userassist", refKey: u.programPath, path: u.programPath, runCount: u.runCount });
  }
  for (const b of data.bam) {
    subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "bam", refKey: b.path, path: b.path, sid: b.sid });
  }
  for (const r of data.autoruns) {
    subjects.push({
      ...BLANK_SUBJECT_FIELDS,
      kind: "autorun",
      refKey: `${r.keyPath}\\${r.valueName ?? ""}`,
      path: r.valueData,
      category: r.category,
      valueName: r.valueName,
      keyPath: r.keyPath,
    });
  }
  // One "prefetch" subject per executable (reuses the existing LOLBin
  // built-in rule against its bare exe name), plus one "prefetch_reference"
  // subject per referenced/loaded file (reuses the existing Temp/Downloads
  // built-in rule against each DLL's own path) — no Prefetch-specific
  // built-in rules needed, both existing rules already apply for free.
  for (const p of data.prefetch ?? []) {
    subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "prefetch", refKey: p.executableName, path: p.executableName, runCount: p.runCount });
    for (const ref of p.referencedFiles) {
      subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "prefetch_reference", refKey: `${p.executableName}:${ref}`, path: ref });
    }
  }
  // Reuses the existing LOLBin/Temp-Downloads built-ins (via `path`) and
  // the new removable/network-path built-in (see rule-engine/seed.ts) —
  // no LNK/JumpList/Shellbag-specific built-in rules needed beyond that one.
  for (const l of data.lnk ?? []) {
    if (!l.targetPath) continue;
    subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "lnk", refKey: l.targetPath, path: l.targetPath });
  }
  for (const j of data.jumplist ?? []) {
    if (!j.targetPath) continue;
    subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "jumplist", refKey: `${j.streamNumber}:${j.targetPath}`, path: j.targetPath });
  }
  for (const s of data.shellbag ?? []) {
    subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "shellbag", refKey: s.path, path: s.path, category: s.itemType });
  }
  // isAllocated false flags a deleted-but-still-present entry;
  // hasTimestomp flags creationTime later than entryModificationTime —
  // the single most forensically-recognized use of raw $MFT data (see
  // the "Possible MFT Timestomping" built-in in rule-engine/seed.ts).
  for (const m of data.mft ?? []) {
    const hasTimestomp = !!(m.creationTime && m.entryModificationTime && new Date(m.creationTime) > new Date(m.entryModificationTime));
    subjects.push({
      ...BLANK_SUBJECT_FIELDS,
      kind: "mft",
      refKey: `${m.mftEntryNumber}`,
      path: m.path ?? m.name,
      isAllocated: m.isAllocated,
      hasTimestomp,
    });
  }
  for (const u of data.usnjrnl ?? []) {
    if (!u.fileName) continue;
    subjects.push({
      ...BLANK_SUBJECT_FIELDS,
      kind: "usnjrnl",
      refKey: `${u.usn}:${u.fileName}`,
      path: u.fileName,
      usnReason: u.reason.join(" "),
    });
  }
  for (const r of data.srum ?? []) {
    subjects.push({
      ...BLANK_SUBJECT_FIELDS,
      kind: "srum",
      refKey: `${r.tableName}:${r.appId ?? ""}:${r.timestamp ?? ""}`,
      path: r.appId,
      providerLabel: r.providerLabel,
    });
  }
  // Reuses the existing LOLBin/Temp-Downloads built-ins via `path` =
  // the crashing module's name — the most forensically useful WER field,
  // since it's often the actual payload (a LOLBin or a dropped file in
  // Temp/Downloads) rather than the host application.
  for (const w of data.wer ?? []) {
    subjects.push({
      ...BLANK_SUBJECT_FIELDS,
      kind: "wer",
      refKey: w.reportGuid ?? `${w.appName ?? ""}:${w.faultModuleName ?? ""}`,
      path: w.faultModuleName ?? w.appName,
      exceptionCode: w.exceptionCode,
    });
  }
  // One subject per loaded module in a minidump — `exceptionCode` is only
  // set on the module whose address range actually contains the
  // exception address (computed below), so a rule on exception_code only
  // fires for the genuinely faulting module, not every DLL the process
  // happened to have loaded.
  for (const d of data.werDump ?? []) {
    let faultingModuleIndex = -1;
    if (d.exceptionAddress) {
      try {
        const exAddr = BigInt(d.exceptionAddress);
        faultingModuleIndex = d.moduleList.findIndex((m) => {
          try {
            const base = BigInt(m.baseAddress);
            return exAddr >= base && exAddr < base + BigInt(m.size);
          } catch {
            return false;
          }
        });
      } catch {
        faultingModuleIndex = -1;
      }
    }
    d.moduleList.forEach((m, i) => {
      subjects.push({
        ...BLANK_SUBJECT_FIELDS,
        kind: "wer_dump_module",
        refKey: `${d.exceptionAddress ?? ""}:${m.name}`,
        path: m.name,
        exceptionCode: i === faultingModuleIndex ? d.exceptionCode : null,
      });
    });
  }
  // Reuses the existing removable-media/network-path built-in via `path`
  // = the deleted item's original location — free reuse, no new rule
  // needed for Recycle Bin specifically.
  for (const r of data.recyclebin ?? []) {
    subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "recyclebin", refKey: r.originalPath, path: r.originalPath });
  }
  // Reuses the existing path-based built-ins via `path` = the transfer's
  // destination (falling back to source URL); `isCarved` feeds the new
  // "Recovered BITS Job Evidence" built-in (see rule-engine/seed.ts).
  for (const b of data.bits ?? []) {
    subjects.push({
      ...BLANK_SUBJECT_FIELDS,
      kind: "bits",
      refKey: `${b.jobId ?? ""}:${b.destFn ?? b.srcFn ?? ""}`,
      path: b.destFn ?? b.srcFn,
      isCarved: b.isCarved,
    });
  }
  // Feeds the new "Defender Quarantine Payload Matches Known Threat-Intel
  // IOC" built-in — identical ioc_known mechanism the existing Amcache
  // SHA1 rule already uses, just a different subject kind/hash field
  // (see iocCandidates() below).
  for (const q of data.quarantinePayload ?? []) {
    subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "quarantine_payload", refKey: q.sha256 ?? "unknown", sha256: q.sha256 });
  }
  // Unlike Search/Notifications, Windows Timeline genuinely has a
  // reliable structured application-identity field — reuses the
  // existing LOLBin/Temp-Downloads path-based built-ins for free via
  // `path`, no new rule needed.
  for (const t of data.timeline ?? []) {
    const identity = t.appDisplayName ?? t.packageIdentifier;
    if (!identity) continue;
    subjects.push({ ...BLANK_SUBJECT_FIELDS, kind: "timeline", refKey: `${t.startTime ?? ""}:${identity}`, path: identity });
  }

  return subjects;
}

/** sha1 (Amcache) and sha256 (decrypted Defender quarantine payload) are
 * the only plausible threat-intel IOCs on a Windows Artifact subject —
 * "path" isn't an IocRecord type (ip/hash/url/domain/email), so ioc_*
 * fields only ever resolve against one of the two hash fields. */
function iocCandidates(subject: WinArtifactRuleSubject): (string | null)[] {
  return [subject.sha1, subject.sha256];
}

function getFieldValue(subject: WinArtifactRuleSubject, field: WinArtifactField, iocMap: IocLookupMap): string {
  if (isIocRuleField(field)) {
    return getIocFieldValue(resolveIoc(iocCandidates(subject), iocMap), field);
  }
  const fieldMap: Record<Exclude<WinArtifactField, IocRuleField>, string | number | boolean | null> = {
    artifact_type:  subject.kind,
    path:           subject.path,
    sha1:           subject.sha1,
    sha256:         subject.sha256,
    run_count:      subject.runCount,
    category:       subject.category,
    value_name:     subject.valueName,
    key_path:       subject.keyPath,
    sid:            subject.sid,
    is_allocated:   subject.isAllocated,
    has_timestomp:  subject.hasTimestomp,
    usn_reason:     subject.usnReason,
    provider_label: subject.providerLabel,
    exception_code: subject.exceptionCode,
    is_carved:      subject.isCarved,
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
