// ─────────────────────────────────────────────────────────────────────────────
// Built-in Rule Seed — inserts the bundled starter detection ruleset into the
// database.
//
// Called from the /api/log-analysis/rules/seed route (admin only). Mirrors
// decoder-engine/seed.ts's delete-all-then-recreate pattern: built-in rows
// are wiped and reinserted on every call, with each rule's enabled state
// preserved across the reseed. These are the only built-in rules Core
// ships — custom rule authoring (new rules, or edits to these) stays an
// Enterprise-only capability, see src/prisma/schema/log-analysis.prisma.
// ─────────────────────────────────────────────────────────────────────────────

import type { Prisma } from "@prisma/client";
import { prisma } from "@/lib/db/prisma";
import type { LogField, RuleCondition, RuleOperator, RuleSeverity } from "@/lib/log-analysis/types";

interface BuiltinRuleDef {
  name: string;
  description: string;
  severity: RuleSeverity;
  logic: "AND" | "OR";
  tags: string[];
  conditions: RuleCondition[];
}

const cond = (field: LogField, operator: RuleOperator, value: string, id: string): RuleCondition =>
  ({ id, field, operator, value });

export const BUILTIN_RULES: BuiltinRuleDef[] = [
  {
    name: "Excessive 404 Responses",
    description: "Possible directory brute-force or scanning",
    severity: "medium",
    logic: "AND",
    tags: ["web", "scanning"],
    conditions: [cond("status_code", "equals", "404", "c1")],
  },
  {
    name: "Encoded PowerShell Command",
    description: "Detects -encodedcommand / -enc usage",
    severity: "high",
    logic: "OR",
    tags: ["execution", "powershell"],
    conditions: [
      cond("command_line", "contains", "-encodedcommand", "c1"),
      cond("command_line", "contains", "-enc ", "c2"),
    ],
  },
  {
    name: "Suspicious LOLBin Execution",
    description: "certutil, mshta, rundll32, regsvr32, wmic, msiexec",
    severity: "high",
    logic: "OR",
    tags: ["execution", "lolbin"],
    conditions: ["certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "msiexec.exe"]
      .map((p, i) => cond("process", "equals", p, `c${i}`)),
  },
  {
    name: "Authentication Failure",
    description: "Failed login attempts",
    severity: "medium",
    logic: "OR",
    tags: ["authentication"],
    conditions: [
      cond("event_type", "equals", "auth_failure", "c1"),
      cond("message", "contains", "failed password", "c2"),
      cond("message", "contains", "authentication failure", "c3"),
    ],
  },
  {
    name: "SQL Injection Attempt",
    description: "Common SQL injection strings in URL or message",
    severity: "high",
    logic: "OR",
    tags: ["web", "sqli"],
    conditions: ["union select", "or 1=1", "sleep(", "information_schema", "' or '", "xp_cmdshell"]
      .map((v, i) => cond("url", "contains", v, `c${i}`)),
  },
  {
    name: "Privilege Escalation (sudo/su)",
    description: "Sudo or su commands detected in syslog",
    severity: "medium",
    logic: "OR",
    tags: ["privilege-escalation"],
    conditions: [
      cond("event_type", "equals", "privilege_escalation", "c1"),
      cond("process", "equals", "sudo", "c2"),
    ],
  },
  {
    name: "C2 Common Ports",
    description: "Outbound connections to common C2 ports (4444, 1337, 5555, 8081, 9001)",
    severity: "critical",
    logic: "OR",
    tags: ["c2", "network"],
    conditions: ["4444", "1337", "5555", "8081", "9001"].map((p, i) => cond("dst_port", "equals", p, `c${i}`)),
  },
  {
    name: "Event Touching a Known Threat-Intel IOC",
    description: "Any IP, domain, URL, or hash on the event already carries prior enrichment from your organization's threat-intel providers",
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
export async function seedBuiltinRules(): Promise<SeedResult> {
  const seeded: string[] = [];
  const errors: { name: string; error: string }[] = [];

  const existing = await prisma.logAnalysisRule.findMany({
    where:  { isBuiltin: true },
    select: { name: true, enabled: true },
  });
  const enabledByName = new Map(existing.map((r) => [r.name, r.enabled]));

  await prisma.logAnalysisRule.deleteMany({ where: { isBuiltin: true } });

  for (const def of BUILTIN_RULES) {
    try {
      const enabled = enabledByName.get(def.name) ?? true;
      await prisma.logAnalysisRule.create({
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
