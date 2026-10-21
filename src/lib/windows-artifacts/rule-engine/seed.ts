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

// Subject kinds that show a program actually ran (or was loaded), as
// opposed to merely existing on disk — see rule-engine.ts's buildSubjects().
const EXECUTION_KINDS = "shimcache,amcache,userassist,bam,prefetch,prefetch_reference,wer,wer_dump_module";

export const BUILTIN_RULES: BuiltinRuleDef[] = [
  // Both path rules below are limited to EXECUTION evidence: Shimcache,
  // Amcache, UserAssist, BAM, Prefetch (the executable and the files it
  // loaded) and WER crash modules. They used to match any artifact path —
  // $MFT/$UsnJrnl/Search entries record that a file EXISTS, not that it ran,
  // and on a real Windows 11 collection that produced ~18,000 "execution
  // from Temp/Downloads" hits (PDFs, desktop.ini, browser caches) and
  // LOLBin hits for System32\rundll32.exe merely being on disk.
  {
    name: "LOLBin in Execution Evidence",
    description: "A living-off-the-land binary commonly abused for execution/defense evasion appears in execution evidence (Shimcache, Amcache, UserAssist, BAM, Prefetch, WER)",
    severity: "high",
    logic: "AND",
    tags: ["execution", "lolbin"],
    conditions: [
      cond("artifact_type", "in_list", EXECUTION_KINDS, "c1"),
      cond("path", "regex", "(^|\\\\|/)(certutil|mshta|rundll32|regsvr32|wmic|msiexec|bitsadmin|powershell)\\.exe$", "c2"),
    ],
  },
  {
    name: "Execution from Temp or Downloads",
    description: "An executable or script ran (or was loaded) from a Temp or Downloads directory — common for dropped/staged malware, though installers also unpack to Temp",
    severity: "medium",
    logic: "AND",
    tags: ["execution", "staging"],
    conditions: [
      cond("artifact_type", "in_list", EXECUTION_KINDS, "c1"),
      cond("path", "regex", "\\\\(Temp|Downloads)\\\\(.*\\\\)?[^\\\\]+\\.(exe|dll|scr|com|pif|cpl|msi|ps1|bat|cmd|vbs|vbe|js|jse|wsf|hta)$", "c2"),
    ],
  },
  {
    name: "Amcache SHA1 Matches Known Threat-Intel IOC",
    description: "This binary's SHA1 hash is known-bad to your organization's threat intel (a threat type, or reputation 70+)",
    severity: "critical",
    logic: "AND",
    tags: ["threat-intel"],
    conditions: [cond("artifact_type", "equals", "amcache", "c1"), cond("ioc_known", "equals", "true", "c2")],
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
    name: "Possible MFT Timestomping",
    description: "A file's NTFS creation timestamp is later than its own MFT record's last-change time. Timestomping tools (SetMACE etc.) produce this, but so does routine software: archive extractors, installers and copy tools set every timestamp — including the MFT change time — to the source file's date (tens of thousands of hits on a normal Windows 11 workstation). Treat as a lead to combine with location and other evidence, not an alert on its own",
    severity: "low",
    logic: "AND",
    tags: ["anti-forensics", "timestomping"],
    conditions: [cond("has_timestomp", "equals", "true", "c1")],
  },
  {
    name: "Recovered BITS Job Evidence",
    description: "A BITS job record was recovered via carving (a partially-deleted/overwritten entry), not clean parsing — attackers and malware commonly delete BITS job records after using BITS to download/stage payloads",
    severity: "medium",
    logic: "AND",
    tags: ["defense-evasion", "bits"],
    conditions: [cond("is_carved", "equals", "true", "c1")],
  },
  {
    name: "Defender Quarantine Payload Matches Known Threat-Intel IOC",
    description: "A decrypted Windows Defender quarantine payload's SHA256 is known-bad to your organization's threat intel (a threat type, or reputation 70+)",
    severity: "critical",
    logic: "AND",
    tags: ["threat-intel", "defender"],
    conditions: [cond("artifact_type", "equals", "quarantine_payload", "c1"), cond("ioc_known", "equals", "true", "c2")],
  },
  {
    name: "Collected File Hash Matches Known Threat-Intel IOC",
    description: "A hash from a Recycle Bin payload, Defender detection history or Defender cloud lookup is known-bad to your organization's threat intel (a threat type, or reputation 70+)",
    severity: "critical",
    logic: "AND",
    tags: ["threat-intel"],
    conditions: [cond("artifact_type", "equals", "artifact_record", "c1"), cond("ioc_known", "equals", "true", "c2")],
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
  // ── registry_plugin subjects (see rule-engine.ts) — category pins the
  // regipy/hand-rolled plugin, summary is its "key=value; ..." summary.
  {
    name: "WDigest Cleartext Credential Caching Enabled",
    description: "HKLM\\SYSTEM\\...\\WDigest\\UseLogonCredential is 1 — LSASS keeps logon passwords in cleartext memory, a classic precursor to credential dumping (often set by attackers before running Mimikatz)",
    severity: "high",
    logic: "AND",
    tags: ["credential-access", "registry"],
    conditions: [
      cond("category", "equals", "wdigest", "c1"),
      cond("summary", "contains", "use_logon_credential=1", "c2"),
    ],
  },
  {
    name: "Image File Execution Options Debugger Set",
    description: "An IFEO key defines a Debugger value — launching that executable runs the debugger instead (persistence/accessibility-feature hijack, e.g. sethc.exe/utilman.exe backdoors)",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "privilege-escalation", "registry"],
    conditions: [
      cond("category", "equals", "image_file_execution_options", "c1"),
      cond("summary", "contains", "Debugger=", "c2"),
    ],
  },
  {
    name: "Autologon Password Stored in LSA Secrets",
    description: "The SECURITY hive holds a DefaultPassword LSA secret — Winlogon autologon is (or was) configured with a stored password that anyone with SYSTEM access can recover",
    severity: "medium",
    logic: "AND",
    tags: ["credential-access", "lsa-secrets"],
    conditions: [
      cond("category", "equals", "forensicator_lsa_secret", "c1"),
      cond("summary", "contains", "secret_name=DefaultPassword", "c2"),
    ],
  },
  {
    name: "Service Runs Under a Stored Account Password",
    description: "An _SC_<service> LSA secret exists — that service logs on with an account whose password is recoverable from the SECURITY/SYSTEM hives (lateral-movement risk if it's a domain account)",
    severity: "low",
    logic: "AND",
    tags: ["credential-access", "lsa-secrets"],
    conditions: [
      cond("category", "equals", "forensicator_lsa_secret", "c1"),
      cond("summary", "regex", "secret_name=_SC_", "c2"),
    ],
  },
  {
    name: "PowerShell Execution Policy Unrestricted or Bypass",
    description: "The machine-wide PowerShell execution policy is Unrestricted or Bypass",
    severity: "low",
    logic: "AND",
    tags: ["execution", "defense-evasion", "powershell"],
    conditions: [
      cond("category", "equals", "execution_policy", "c1"),
      cond("summary", "regex", "execution_policy=(Unrestricted|Bypass)", "c2"),
    ],
  },
  {
    name: "Windows Defender Disabled via Registry",
    description: "Windows Defender's registry configuration has antivirus or antispyware protection disabled",
    severity: "high",
    logic: "AND",
    tags: ["defense-evasion", "defender"],
    conditions: [
      cond("category", "equals", "windows_defender", "c1"),
      cond("summary", "regex", "(antivirus_disabled|antispyware_disabled)=true", "c2"),
    ],
  },
  {
    name: "Enabled Local Account With 'Password Not Required'",
    description: "An enabled local SAM account carries the PASSWD_NOTREQD flag — it may be allowed a blank password",
    severity: "medium",
    logic: "AND",
    tags: ["credential-access", "accounts"],
    conditions: [
      cond("category", "equals", "samparse", "c1"),
      cond("summary", "contains", "Password Not Required", "c2"),
      cond("summary", "not_contains", "Account Disabled", "c3"),
    ],
  },
  {
    name: "LSA Notification Package Beyond Windows Defaults",
    description: "HKLM\\SYSTEM\\...\\Lsa Notification Packages lists something other than scecli/rassfm — a password-filter DLL here receives every password change in cleartext",
    severity: "high",
    logic: "AND",
    tags: ["credential-access", "persistence", "lsa"],
    conditions: [
      cond("category", "equals", "lsa_packages", "c1"),
      cond("summary", "regex", "notification_packages=(?!(scecli|rassfm)(,(scecli|rassfm))*(;|$))", "c2"),
    ],
  },
  {
    name: "Cached Domain Logon Present",
    description: "A populated NL$ cached-logon record in the SECURITY hive — a domain account has logged on interactively here (its hash is crackable offline); the record's last_cached_logon gives when",
    severity: "info",
    logic: "AND",
    tags: ["credential-access", "lateral-movement"],
    conditions: [
      cond("category", "equals", "forensicator_cached_logon", "c1"),
      cond("summary", "contains", "populated=true", "c2"),
    ],
  },
  // ── artifact_record subjects (Stage-2 artifact types, see rule-engine.ts)
  {
    name: "WMI Event Consumer Runs a Command or Script",
    description: "A WMI permanent event subscription uses a CommandLineEventConsumer or ActiveScriptEventConsumer that isn't a known Windows/OEM default — a classic fileless persistence mechanism",
    severity: "critical",
    logic: "AND",
    tags: ["persistence", "wmi"],
    conditions: [
      cond("category", "regex", "^wmi_(consumer|binding|repository_hit)$", "c1"),
      cond("summary", "contains", "suspicious_type=true", "c2"),
    ],
  },
  {
    name: "Microsoft Defender Detection Recorded",
    description: "Defender's own detection history or support log records a threat on this host — even if remediated, the detected file/script and the user/process involved are the starting point",
    severity: "high",
    logic: "AND",
    tags: ["malware", "defender"],
    conditions: [cond("category", "regex", "^defender_(detection|log_detection)$", "c1")],
  },
  {
    name: "Defender Exclusion Activity in Support Log",
    description: "Defender's support log records an exclusion (path/extension/process/IP) — attackers add exclusions to keep tooling from being scanned",
    severity: "medium",
    logic: "AND",
    tags: ["defense-evasion", "defender"],
    conditions: [cond("category", "equals", "defender_exclusion", "c1")],
  },
  {
    name: "Defender Protection Tampering in Support Log",
    description: "Defender's support log records real-time protection being disabled or a tamper-protection event",
    severity: "high",
    logic: "AND",
    tags: ["defense-evasion", "defender"],
    conditions: [cond("category", "equals", "defender_tamper", "c1")],
  },
  {
    name: "Remote Access Tool Session",
    description: "AnyDesk/TeamViewer (or similar) logs record a remote session — confirm it was authorised; attackers and support scammers use these tools for hands-on access",
    severity: "medium",
    logic: "AND",
    tags: ["remote-access", "lateral-movement"],
    conditions: [cond("category", "equals", "remote_access_connection", "c1")],
  },
  {
    name: "Unsaved Editor Text Mentions Credentials",
    description: "Recovered Notepad/Notepad++ unsaved text contains password/token/API-key wording — possible plaintext credentials on the host",
    severity: "medium",
    logic: "AND",
    tags: ["credential-access", "unsecured-credentials"],
    conditions: [
      cond("category", "equals", "notepad_document", "c1"),
      cond("summary", "contains", "mentions_credentials=true", "c2"),
    ],
  },
  {
    name: "Recycle Bin Payload Is an Executable or Script",
    description: "A deleted file still in the Recycle Bin is a PE executable or script — deleted tooling is worth recovering and hashing",
    severity: "medium",
    logic: "AND",
    tags: ["defense-evasion", "indicator-removal"],
    conditions: [
      cond("category", "equals", "recycle_payload", "c1"),
      cond("summary", "regex", "file_type=(PE executable|PowerShell script|batch script|script)", "c2"),
    ],
  },
  {
    name: "PowerShell Download/Encoded Command in Pagefile or Swapfile",
    description: "Encoded-command or download-cradle PowerShell text was recovered from pagefile.sys/swapfile.sys/hiberfil.sys — evidence of execution that may no longer exist anywhere else on disk",
    severity: "high",
    logic: "AND",
    tags: ["execution", "powershell", "memory"],
    conditions: [
      cond("category", "equals", "memory_ioc", "c1"),
      cond("summary", "contains", "indicator_type=powershell", "c2"),
    ],
  },
  {
    name: "Possible Timestomping in $LogFile FILE_NAME Record",
    description: "A $FILE_NAME attribute carved from $LogFile has a creation time later than its MFT-entry modification time — not produced by normal file-system activity",
    severity: "medium",
    logic: "AND",
    tags: ["anti-forensics", "timestomping"],
    conditions: [
      cond("category", "equals", "logfile_filename", "c1"),
      cond("summary", "contains", "possible_timestomp=true", "c2"),
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
