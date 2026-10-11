// ─────────────────────────────────────────────────────────────────────────────
// Built-in Rule Seed — inserts the bundled starter detection ruleset into the
// database.
//
// Called from the /api/pcap-analysis/rules/seed route (admin only). Mirrors
// log-analysis/rule-engine/seed.ts's delete-all-then-recreate pattern: built-
// in rows are wiped and reinserted on every call, with each rule's enabled
// state preserved across the reseed. The first 5 are the overlay's own
// STARTER_TEMPLATES (its rules/page.tsx had a click-to-add flow for these,
// never a real built-in/custom split); the last 3 are new, added since Core
// shipped with none before. Custom rule authoring (new rules, or edits to
// these) stays an Enterprise-only capability, see
// src/prisma/schema/pcap-analysis.prisma.
// ─────────────────────────────────────────────────────────────────────────────

import { prisma } from "@/lib/db/prisma";
import type { Prisma } from "@prisma/client";
import type { PcapField, PcapRuleCondition, RuleSeverity } from "@/lib/pcap-analysis/types";
import type { RuleOperator } from "@/lib/rule-engine/operators";

interface BuiltinRuleDef {
  name: string;
  description: string;
  severity: RuleSeverity;
  logic: "AND" | "OR";
  tags: string[];
  conditions: PcapRuleCondition[];
}

const cond = (field: PcapField, operator: RuleOperator, value: string, id: string): PcapRuleCondition =>
  ({ id, field, operator, value });

export const BUILTIN_RULES: BuiltinRuleDef[] = [
  {
    name: "C2 Common Ports",
    description: "Conversation to a common C2/backdoor port (23, 3389, 4444, 1080, 6667)",
    severity: "critical",
    logic: "OR",
    tags: ["c2", "network"],
    conditions: ["23", "3389", "4444", "1080", "6667"].map((p, i) => cond("port_b", "equals", p, `c${i}`)),
  },
  {
    name: "High-Volume Transfer",
    description: "Single conversation exceeding 200MB — possible bulk exfiltration",
    severity: "high",
    logic: "AND",
    tags: ["exfiltration"],
    conditions: [cond("bytes_total", "greater_than", "209715200", "c1")],
  },
  {
    name: "Suspicious TLS SNI Pattern",
    description: "TLS handshake to a domain matching a suspicious pattern",
    severity: "medium",
    logic: "OR",
    tags: ["c2", "tls"],
    conditions: [
      cond("tls_sni", "contains", ".xyz", "c1"),
      cond("tls_sni", "contains", ".top", "c2"),
    ],
  },
  {
    name: "DNS Query to Dynamic DNS Provider",
    description: "Common dynamic-DNS domains sometimes abused for C2",
    severity: "medium",
    logic: "OR",
    tags: ["c2", "dns"],
    conditions: ["duckdns.org", "no-ip.com", "ddns.net"].map((d, i) => cond("dns_query", "contains", d, `c${i}`)),
  },
  {
    name: "Conversation with a Known Threat-Intel IOC",
    description: "Either endpoint, DNS query, or TLS SNI already carries prior enrichment from your organization's threat-intel providers",
    severity: "critical",
    logic: "AND",
    tags: ["threat-intel"],
    conditions: [cond("ioc_known", "equals", "true", "c1")],
  },
  {
    name: "DNS Query to Suspicious TLD",
    description: "DNS query for a domain under a TLD commonly abused for cheap/throwaway malicious infrastructure",
    severity: "medium",
    logic: "OR",
    tags: ["dns", "c2"],
    conditions: [".xyz", ".top", ".club"].map((tld, i) => cond("dns_query", "contains", tld, `c${i}`)),
  },
  {
    name: "Tor Network Ports",
    description: "Conversation on a common Tor relay/directory port (9001, 9030, 9050) — possible anonymization proxy use",
    severity: "medium",
    logic: "OR",
    tags: ["tor", "anonymity"],
    conditions: ["9001", "9030", "9050"].map((p, i) => cond("port_b", "equals", p, `c${i}`)),
  },
  {
    name: "Cleartext FTP Control Channel",
    description: "Conversation on FTP's control port (21) — credentials and commands are sent unencrypted",
    severity: "low",
    logic: "AND",
    tags: ["cleartext"],
    conditions: [cond("port_b", "equals", "21", "c1")],
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
export async function seedBuiltinPcapRules(): Promise<SeedResult> {
  const seeded: string[] = [];
  const errors: { name: string; error: string }[] = [];

  const existing = await prisma.pcapAnalysisRule.findMany({
    where:  { isBuiltin: true },
    select: { name: true, enabled: true },
  });
  const enabledByName = new Map(existing.map((r) => [r.name, r.enabled]));

  await prisma.pcapAnalysisRule.deleteMany({ where: { isBuiltin: true } });

  for (const def of BUILTIN_RULES) {
    try {
      const enabled = enabledByName.get(def.name) ?? true;
      await prisma.pcapAnalysisRule.create({
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
