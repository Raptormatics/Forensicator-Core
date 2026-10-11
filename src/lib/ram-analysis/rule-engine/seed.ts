// ─────────────────────────────────────────────────────────────────────────────
// Built-in Rule Seed — inserts the bundled starter detection ruleset into the
// database.
//
// Called from the /api/ram-analysis/rules/seed route (admin only). Mirrors
// log-analysis/rule-engine/seed.ts and pcap-analysis/rule-engine/seed.ts's
// delete-all-then-recreate pattern: built-in rows are wiped and reinserted
// on every call, with each rule's enabled state preserved across the
// reseed. Field vocabulary confirmed against rule-engine.ts's real
// getFieldValue() field map — each rule here is a single flat AND/OR
// across its own conditions (the engine has no nested boolean logic), so
// these are deliberately single-signal detections, not compound ones.
// Custom rule authoring (new rules, or edits to these) stays an
// Enterprise-only capability, see src/prisma/schema/ram-analysis.prisma.
// ─────────────────────────────────────────────────────────────────────────────

import { prisma } from "@/lib/db/prisma";
import type { Prisma } from "@prisma/client";
import type { RamField, RamRuleCondition, RuleSeverity } from "@/lib/ram-analysis/types";
import type { RuleOperator } from "@/lib/rule-engine/operators";

interface BuiltinRuleDef {
  name: string;
  description: string;
  severity: RuleSeverity;
  logic: "AND" | "OR";
  tags: string[];
  conditions: RamRuleCondition[];
}

const cond = (field: RamField, operator: RuleOperator, value: string, id: string): RamRuleCondition =>
  ({ id, field, operator, value });

export const BUILTIN_RULES: BuiltinRuleDef[] = [
  {
    name: "LOLBin Process Execution",
    description: "A living-off-the-land binary commonly abused for execution/defense evasion was found running",
    severity: "high",
    logic: "OR",
    tags: ["execution", "lolbin"],
    conditions: ["certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe"]
      .map((p, i) => cond("process_name", "equals", p, `c${i}`)),
  },
  {
    name: "Encoded PowerShell Command",
    description: "A running process's command line contains -encodedcommand / -enc usage",
    severity: "high",
    logic: "OR",
    tags: ["execution", "powershell"],
    conditions: [
      cond("command_line", "contains", "-encodedcommand", "c1"),
      cond("command_line", "contains", "-enc ", "c2"),
    ],
  },
  {
    name: "PowerShell Execution-Policy Bypass",
    description: "A running process's command line requests a hidden window or bypasses the execution policy",
    severity: "medium",
    logic: "OR",
    tags: ["execution", "powershell"],
    conditions: [
      cond("command_line", "contains", "-executionpolicy bypass", "c1"),
      cond("command_line", "contains", "-windowstyle hidden", "c2"),
    ],
  },
  {
    name: "Process Running from a Temp Directory",
    description: "A process is executing from a temporary directory — common for dropped/staged payloads",
    severity: "medium",
    logic: "OR",
    tags: ["persistence"],
    conditions: [
      cond("process_path", "contains", "\\Temp\\", "c1"),
      cond("process_path", "contains", "/tmp/", "c2"),
    ],
  },
  {
    name: "Outbound Connection on a Common C2 Port",
    description: "A network connection uses a port commonly associated with C2/backdoor frameworks (4444, 8080, 8443, 1337, 6667)",
    severity: "critical",
    logic: "OR",
    tags: ["c2", "network"],
    conditions: ["4444", "8080", "8443", "1337", "6667"].map((p, i) => cond("remote_port", "equals", p, `c${i}`)),
  },
  {
    name: "Network Connection to a Known Threat-Intel IOC",
    description: "A connection's remote address already carries prior enrichment from your organization's threat-intel providers",
    severity: "critical",
    logic: "AND",
    tags: ["threat-intel"],
    conditions: [cond("ioc_known", "equals", "true", "c1")],
  },
];

export interface SeedResult {
  seeded: string[];
  errors: { name: string; error: string }[];
}

/**
 * Wipe and recreate all `isBuiltin: true` rules from BUILTIN_RULES.
 * Preserves each rule's `enabled` state across re-seeds.
 */
export async function seedBuiltinRamRules(): Promise<SeedResult> {
  const seeded: string[] = [];
  const errors: { name: string; error: string }[] = [];

  const existing = await prisma.ramAnalysisRule.findMany({
    where:  { isBuiltin: true },
    select: { name: true, enabled: true },
  });
  const enabledByName = new Map(existing.map((r) => [r.name, r.enabled]));

  await prisma.ramAnalysisRule.deleteMany({ where: { isBuiltin: true } });

  for (const def of BUILTIN_RULES) {
    try {
      const enabled = enabledByName.get(def.name) ?? true;
      await prisma.ramAnalysisRule.create({
        data: {
          name:        def.name,
          description: def.description,
          severity:    def.severity,
          enabled,
          isBuiltin:   true,
          logic:       def.logic,
          conditions:  def.conditions as unknown as Prisma.InputJsonValue,
          tags:        def.tags,
        },
      });
      seeded.push(def.name);
    } catch (err) {
      errors.push({ name: def.name, error: String(err) });
    }
  }

  return { seeded, errors };
}
