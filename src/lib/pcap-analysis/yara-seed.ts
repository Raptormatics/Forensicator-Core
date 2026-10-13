// ─────────────────────────────────────────────────────────────────────────────
// Built-in Yara Signature Seed — inserts a small, conservative set of
// well-known indicator-string signatures into the database.
//
// Called from the /api/pcap-analysis/yara-rules/seed route. Mirrors
// ram-analysis/yara-seed.ts's delete-all-then-recreate pattern: built-in
// rows are wiped and reinserted on every call, with each rule's enabled
// state preserved across the reseed. Same indicator strings as RAM's set —
// they're valid regardless of medium (a Cobalt Strike beacon or Mimikatz
// output can show up in cleartext capture payloads too), kept as an
// independent copy rather than a shared import since every other rule
// domain in this codebase (log-analysis, RAM, PCAP) already keeps its own
// self-contained BUILTIN_RULES array.
// ─────────────────────────────────────────────────────────────────────────────

import { prisma } from "@/lib/db/prisma";
import type { RuleSeverity } from "@/lib/pcap-analysis/types";

interface BuiltinYaraRuleDef {
  name: string;
  description: string;
  severity: RuleSeverity;
  tags: string[];
  yaraSource: string;
}

export const BUILTIN_YARA_RULES: BuiltinYaraRuleDef[] = [
  {
    name: "Mimikatz Indicators",
    description: "Strings commonly found in Mimikatz and its forks (credential-dumping tool)",
    severity: "critical",
    tags: ["credential-access"],
    yaraSource: `rule Mimikatz_Indicators
{
    meta:
        description = "Strings commonly found in Mimikatz and its forks"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "gentilkiwi" ascii wide nocase
        $s3 = "mimikatz" ascii wide nocase
    condition:
        any of them
}
`,
  },
  {
    name: "Cobalt Strike / Metasploit Reflective Loader",
    description: "Reflective DLL loader export name used by Cobalt Strike and Metasploit",
    severity: "critical",
    tags: ["c2"],
    yaraSource: `rule CobaltStrike_Metasploit_ReflectiveLoader
{
    meta:
        description = "Reflective DLL loader export name used by Cobalt Strike and Metasploit"
    strings:
        $s1 = "ReflectiveLoader" ascii wide
    condition:
        any of them
}
`,
  },
  {
    name: "PowerShell Empire Indicators",
    description: "Strings associated with the PowerShell Empire post-exploitation framework",
    severity: "high",
    tags: ["c2", "powershell"],
    yaraSource: `rule PowerShell_Empire_Indicators
{
    meta:
        description = "Strings associated with the PowerShell Empire post-exploitation framework"
    strings:
        $s1 = "Invoke-Mimikatz" ascii wide nocase
        $s2 = "System.Management.Automation.Runspaces" ascii wide
        $s3 = "get-keystrokes" ascii wide nocase
    condition:
        any of them
}
`,
  },
  {
    name: "Generic Ransom Note String",
    description: "Common phrasing seen in ransomware ransom notes, e.g. staged for exfil or dropped over SMB/HTTP",
    severity: "high",
    tags: ["ransomware"],
    yaraSource: `rule Generic_Ransom_Note_String
{
    meta:
        description = "Common phrasing seen in ransomware ransom notes"
    strings:
        $s1 = "Your files have been encrypted" ascii wide nocase
        $s2 = "All your files are encrypted" ascii wide nocase
        $s3 = "decrypt your files" ascii wide nocase
    condition:
        any of them
}
`,
  },
];

export interface SeedResult {
  seeded: string[];
  errors: { name: string; error: string }[];
}

/**
 * Wipe and recreate all `isBuiltin: true` Yara rules from BUILTIN_YARA_RULES.
 * Preserves each rule's `enabled` state across re-seeds.
 */
export async function seedBuiltinYaraRules(): Promise<SeedResult> {
  const seeded: string[] = [];
  const errors: { name: string; error: string }[] = [];

  const existing = await prisma.pcapYaraRule.findMany({
    where:  { isBuiltin: true },
    select: { name: true, enabled: true },
  });
  const enabledByName = new Map(existing.map((r) => [r.name, r.enabled]));

  await prisma.pcapYaraRule.deleteMany({ where: { isBuiltin: true } });

  for (const def of BUILTIN_YARA_RULES) {
    try {
      const enabled = enabledByName.get(def.name) ?? true;
      await prisma.pcapYaraRule.create({
        data: {
          name:        def.name,
          description: def.description,
          severity:    def.severity,
          enabled,
          isBuiltin:   true,
          yaraSource:  def.yaraSource,
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
