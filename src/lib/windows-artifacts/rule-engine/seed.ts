// ─────────────────────────────────────────────────────────────────────────────
// Built-in Rule Seed — inserts the bundled starter detection ruleset into the
// database.
//
// Called from /api/windows-artifacts/rules/seed (admin only). Mirrors
// ram-analysis/rule-engine/seed.ts's delete-all-then-recreate pattern:
// built-in rows are wiped and reinserted on every call, with each rule's
// enabled state preserved across the reseed. Field vocabulary confirmed
// against rule-engine.ts's real getFieldValue() field map — each rule here
// is a single flat AND/OR across its own conditions (the engine has no
// nested boolean logic). Custom rule authoring stays an Enterprise-only
// capability, see src/prisma/schema/windows-artifacts.prisma.
// ─────────────────────────────────────────────────────────────────────────────

import { prisma } from "@/lib/db/prisma";
import type { Prisma } from "@prisma/client";
import type { WinArtifactField, WinArtifactRuleCondition, RuleSeverity } from "@/lib/windows-artifacts/types";
import type { RuleOperator } from "@/lib/rule-engine/operators";

interface BuiltinRuleDef {
  name: string;
  description: string;
  severity: RuleSeverity;
  logic: "AND" | "OR";
  tags: string[];
  conditions: WinArtifactRuleCondition[];
}

const cond = (field: WinArtifactField, operator: RuleOperator, value: string, id: string): WinArtifactRuleCondition =>
  ({ id, field, operator, value });

export const BUILTIN_RULES: BuiltinRuleDef[] = [
  {
    name: "LOLBin in Execution Evidence",
    description: "A living-off-the-land binary commonly abused for execution/defense evasion appears in Shimcache, Amcache, or UserAssist",
    severity: "high",
    logic: "OR",
    tags: ["execution", "lolbin"],
    conditions: ["certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "msiexec.exe", "bitsadmin.exe", "powershell.exe"]
      .map((p, i) => cond("path", "contains", p, `c${i}`)),
  },
  {
    name: "Execution from Temp or Downloads",
    description: "A binary ran from a Temp or Downloads directory — common for dropped/staged malware",
    severity: "medium",
    logic: "OR",
    tags: ["execution", "staging"],
    conditions: [
      cond("path", "contains", "\\Temp\\", "c1"),
      cond("path", "contains", "\\Downloads\\", "c2"),
      cond("path", "contains", "\\AppData\\Local\\Temp\\", "c3"),
    ],
  },
  {
    name: "Amcache SHA1 Matches Known Threat-Intel IOC",
    description: "This binary's SHA1 hash already carries prior enrichment from your organization's threat-intel providers",
    severity: "critical",
    logic: "AND",
    tags: ["threat-intel"],
    conditions: [cond("ioc_known", "equals", "true", "c1")],
  },
  {
    name: "Service ImagePath Outside Standard Directories",
    description: "A service's executable path isn't under System32 or Program Files — a common persistence/masquerading technique",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "service"],
    conditions: [
      cond("category", "equals", "service", "c1"),
      cond("path", "not_contains", "System32", "c2"),
      cond("path", "not_contains", "Program Files", "c3"),
    ],
  },
  {
    name: "Winlogon Shell Value Altered",
    description: "The Winlogon Shell value doesn't reference explorer.exe — a classic shell-replacement persistence technique",
    severity: "critical",
    logic: "AND",
    tags: ["persistence", "winlogon"],
    conditions: [
      cond("category", "equals", "winlogon_shell", "c1"),
      cond("path", "not_contains", "explorer.exe", "c2"),
    ],
  },
  {
    name: "LNK/Jump List/Shellbag Target on Removable or Network Path",
    description: "A shortcut, jump-list entry, or shellbag-reconstructed folder path points to a non-system local drive letter (removable media) or a UNC network share",
    severity: "medium",
    logic: "OR",
    tags: ["lateral-movement", "removable-media"],
    conditions: [
      cond("path", "regex", "^[D-Zd-z]:\\\\", "c1"),
      cond("path", "starts_with", "\\\\", "c2"),
    ],
  },
  {
    name: "AppInit_DLLs Configured",
    description: "AppInit_DLLs is set — a DLL-injection persistence vector affecting every process that loads user32.dll",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "injection"],
    conditions: [
      cond("value_name", "equals", "AppInit_DLLs", "c1"),
      cond("path", "not_equals", "", "c2"),
    ],
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
export async function seedBuiltinWinArtifactRules(): Promise<SeedResult> {
  const seeded: string[] = [];
  const errors: { name: string; error: string }[] = [];

  const existing = await prisma.windowsArtifactRule.findMany({
    where:  { isBuiltin: true },
    select: { name: true, enabled: true },
  });
  const enabledByName = new Map(existing.map((r) => [r.name, r.enabled]));

  await prisma.windowsArtifactRule.deleteMany({ where: { isBuiltin: true } });

  for (const def of BUILTIN_RULES) {
    try {
      const enabled = enabledByName.get(def.name) ?? true;
      await prisma.windowsArtifactRule.create({
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
