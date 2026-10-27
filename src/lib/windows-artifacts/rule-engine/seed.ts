// ─────────────────────────────────────────────────────────────────────────────
// Built-in Rule Seed — inserts the bundled starter detection ruleset into the
// database.
//
// Called from /api/host-artifacts/rules/seed (admin only). Mirrors
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
  // ── Linux collector artifacts (linux-parse.py) — category is the record
  // kind, and each record's summary starts with "findings=<traits>".
  {
    name: "Linux: Non-Root Account With UID 0",
    description: "An account other than root has UID 0 — a second root account, a classic backdoor",
    severity: "critical",
    logic: "AND",
    tags: ["persistence", "privilege-escalation", "linux"],
    conditions: [
      cond("category", "regex", "^linux_account$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(uid0_non_root)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Account With an Empty Password",
    description: "/etc/shadow has an account with an empty password field — anyone can log in as it where password authentication is allowed",
    severity: "high",
    logic: "AND",
    tags: ["credential-access", "linux"],
    conditions: [
      cond("category", "regex", "^linux_shadow$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(empty_password)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Reverse Shell Command",
    description: "A shell history, cron job, systemd unit or startup file contains a reverse-shell construct (/dev/tcp, nc -e, socat exec, interactive bash redirected to a socket)",
    severity: "critical",
    logic: "AND",
    tags: ["execution", "command-and-control", "linux"],
    conditions: [
      cond("category", "regex", "^linux_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(reverse_shell)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Download and Execute",
    description: "A command downloads content and runs it (curl/wget piped into a shell, or saved to a temp dir and executed)",
    severity: "high",
    logic: "AND",
    tags: ["execution", "ingress-tool-transfer", "linux"],
    conditions: [
      cond("category", "regex", "^linux_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(download_exec)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Encoded Command Execution",
    description: "A base64-decoded payload is piped into a shell or evaluated",
    severity: "high",
    logic: "AND",
    tags: ["execution", "obfuscation", "linux"],
    conditions: [
      cond("category", "regex", "^linux_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(encoded_exec)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Log or History Clearing",
    description: "A command removes or truncates files in /var/log, vacuums the journal, or clears/disables shell history",
    severity: "high",
    logic: "AND",
    tags: ["defense-evasion", "anti-forensics", "linux"],
    conditions: [
      cond("category", "regex", "^linux_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(log_clearing)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Shell History Disabled",
    description: "A shell history file is a symlink to /dev/null — commands typed in that shell are never recorded",
    severity: "medium",
    logic: "AND",
    tags: ["defense-evasion", "anti-forensics", "linux"],
    conditions: [
      cond("category", "regex", "^linux_symlink$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(history_disabled)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Scheduled Task or Service Runs From a Temp Directory",
    description: "A cron job, systemd unit or startup file runs something from /tmp, /var/tmp or /dev/shm",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "linux"],
    conditions: [
      cond("category", "regex", "^linux_(cron_job|cron_script|systemd_unit|config_line)$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(mentions_temp_path)\\b", "c2"),
    ],
  },
  {
    name: "Linux: SSH Key With a Forced Command or Environment",
    description: "An authorized_keys entry carries command= or environment= — the key runs a fixed program (often a backdoor) on every login",
    severity: "medium",
    logic: "AND",
    tags: ["persistence", "linux"],
    conditions: [
      cond("category", "regex", "^linux_ssh_authorized_key$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(forced_command|environment_option)\\b", "c2"),
    ],
  },
  {
    name: "Linux: authorized_keys in an Unusual Location",
    description: "An authorized_keys file outside /home and /root — check sshd_config's AuthorizedKeysFile for a planted path",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "linux"],
    conditions: [
      cond("category", "regex", "^linux_ssh_authorized_key$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(unusual_location)\\b", "c2"),
    ],
  },
  {
    name: "Linux: /etc/ld.so.preload Entry",
    description: "/etc/ld.so.preload loads a library into every dynamically linked process — the standard userland-rootkit hook",
    severity: "critical",
    logic: "AND",
    tags: ["persistence", "defense-evasion", "rootkit", "linux"],
    conditions: [
      cond("category", "regex", "^linux_config_line$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(ld_preload_entry)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Possible PAM Backdoor",
    description: "A PAM stack runs pam_exec or loads a module from outside the system library directories — can capture passwords or accept any password",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "credential-access", "linux"],
    conditions: [
      cond("category", "regex", "^linux_config_line$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(pam_backdoor_candidate)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Hook Persistence (udev, modprobe, core_pattern, package manager)",
    description: "A udev RUN+= rule, modprobe install directive, kernel.core_pattern pipe or unusual package-manager hook runs a program on a system event",
    severity: "medium",
    logic: "AND",
    tags: ["persistence", "linux"],
    conditions: [
      cond("category", "regex", "^linux_config_line$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(udev_run|modprobe_install_hook|core_pattern_pipe|package_manager_hook)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Process Running From a Deleted Executable",
    description: "A running process's executable has been deleted from disk — typical of fileless or self-deleting malware (the collector recovers the binary from /proc)",
    severity: "critical",
    logic: "AND",
    tags: ["defense-evasion", "execution", "linux"],
    conditions: [
      cond("category", "regex", "^linux_(process|recovered_executable)$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(deleted_executable)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Process Executable in a Temp Directory",
    description: "A running process's executable lives in /tmp, /var/tmp or /dev/shm",
    severity: "high",
    logic: "AND",
    tags: ["execution", "linux"],
    conditions: [
      cond("category", "regex", "^linux_process$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(exe_in_temp)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Process Name Masquerading",
    description: "A process's name differs from its executable, and the executable is outside the system directories — e.g. a binary in /dev/shm calling itself sshd",
    severity: "high",
    logic: "AND",
    tags: ["defense-evasion", "masquerading", "linux"],
    conditions: [
      cond("category", "regex", "^linux_process$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(masquerade)\\b", "c2"),
    ],
  },
  {
    name: "Linux: SUID File in a Temp or Home Directory",
    description: "A set-uid/set-gid file outside the system directories — a planted root shell is the usual reason",
    severity: "high",
    logic: "AND",
    tags: ["privilege-escalation", "persistence", "linux"],
    conditions: [
      cond("category", "regex", "^linux_fs_entry$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(suid_in_user_or_temp_dir)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Hidden File in a Temp Directory",
    description: "A dot-file in /tmp, /var/tmp, /dev/shm or /dev other than the standard X11/ICE socket folders",
    severity: "medium",
    logic: "AND",
    tags: ["defense-evasion", "linux"],
    conditions: [
      cond("category", "regex", "^linux_fs_entry$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(hidden_file_in_temp|deceptive_name)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Immutable Attribute on a Persistence or Credential File",
    description: "chattr +i/+a is set on a file in a persistence or credential location — keeps planted persistence from being edited or removed",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "defense-evasion", "linux"],
    conditions: [
      cond("category", "regex", "^linux_immutable_file$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(immutable_attribute)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Privileged or Host-Mounted Container",
    description: "A Docker container runs privileged, shares the host's PID/network namespace, or mounts / or the Docker socket — a container breakout path",
    severity: "high",
    logic: "AND",
    tags: ["privilege-escalation", "container", "linux"],
    conditions: [
      cond("category", "regex", "^linux_container$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(privileged_container|host_mount|host_namespace)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Kernel Tainted by an Out-of-Tree or Unsigned Module",
    description: "The running kernel loaded an out-of-tree or unsigned module — check lsmod for a rootkit",
    severity: "medium",
    logic: "AND",
    tags: ["rootkit", "linux"],
    conditions: [
      cond("category", "regex", "^linux_kernel_taint$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(out_of_tree_module|unsigned_module)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Non-systemd eBPF Program Loaded",
    description: "An eBPF program not attached by systemd is loaded — eBPF backdoors (BPFDoor and others) live here",
    severity: "medium",
    logic: "AND",
    tags: ["rootkit", "defense-evasion", "linux"],
    conditions: [
      cond("category", "regex", "^linux_bpf_program$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(non_systemd_bpf_program)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Attack or Reconnaissance Tool Used",
    description: "A shell history, process or scheduled task references an attack tool (chisel, sliver, msfvenom, xmrig, ...) or privilege-escalation recon (linpeas, pspy, SUID sweeps, reading /etc/shadow)",
    severity: "high",
    logic: "AND",
    tags: ["discovery", "execution", "linux"],
    conditions: [
      cond("category", "regex", "^linux_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(attack_tool|recon)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Broad sudo Grant",
    description: "A sudoers entry grants ALL to a non-default user, or weakens sudo (!authenticate, LD_PRELOAD kept)",
    severity: "medium",
    logic: "AND",
    tags: ["privilege-escalation", "linux"],
    conditions: [
      cond("category", "regex", "^linux_sudoers$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(full_root_grant|weakened_sudo)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Kernel init= Override",
    description: "The kernel command line starts a non-standard init — runs attacker code as PID 1",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "linux"],
    conditions: [
      cond("category", "regex", "^linux_kernel_cmdline$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(init_override)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Shell or Interpreter Holding a Network Socket",
    description: "bash, sh, python, perl, nc, socat or php owns a network socket — the shape of a live reverse or bind shell",
    severity: "high",
    logic: "AND",
    tags: ["command-and-control", "execution", "linux"],
    conditions: [
      cond("category", "regex", "^linux_socket$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(shell_or_interpreter_socket)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Container Escape Command",
    description: "A command starts a privileged/host-mounted container or nsenters PID 1",
    severity: "high",
    logic: "AND",
    tags: ["privilege-escalation", "container", "linux"],
    conditions: [
      cond("category", "regex", "^linux_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(container_escape)\\b", "c2"),
    ],
  },
  {
    name: "Linux: Weak SSH Server Setting",
    description: "sshd allows root login with a password, empty passwords, password authentication or an AuthorizedKeysCommand",
    severity: "low",
    logic: "AND",
    tags: ["initial-access", "linux"],
    conditions: [
      cond("category", "regex", "^linux_config_line$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(weak_sshd_setting)\\b", "c2"),
    ],
  },  // ── macOS collector artifacts (mac-parse.py) — same shape as the Linux
  // rules: category is the record kind, summary starts "findings=<traits>".
  {
    name: "macOS: Non-Root Account With UID 0",
    description: "A Directory Services account other than root has UID 0 — a second root account, a classic backdoor",
    severity: "critical",
    logic: "AND",
    tags: ["persistence", "privilege-escalation", "macos"],
    conditions: [
      cond("category", "regex", "^mac_account$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(uid0_non_root)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Hidden User Account",
    description: "A regular account (UID 500 or above) is hidden from the login window and System Settings (IsHidden) — used to hide a backdoor account",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "defense-evasion", "macos"],
    conditions: [
      cond("category", "regex", "^mac_account$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(hidden_user)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Reverse Shell Command",
    description: "A shell history, launch item, cron job or startup file contains a reverse-shell construct (/dev/tcp, nc -e, socat exec, interactive bash redirected to a socket)",
    severity: "critical",
    logic: "AND",
    tags: ["execution", "command-and-control", "macos"],
    conditions: [
      cond("category", "regex", "^mac_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(reverse_shell)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Download and Execute",
    description: "A command downloads content and runs it (curl/wget piped into a shell, or saved to a temp folder and executed)",
    severity: "high",
    logic: "AND",
    tags: ["execution", "ingress-tool-transfer", "macos"],
    conditions: [
      cond("category", "regex", "^mac_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(download_exec)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Encoded Command Execution",
    description: "A command decodes base64 and runs it",
    severity: "high",
    logic: "AND",
    tags: ["execution", "obfuscation", "macos"],
    conditions: [
      cond("category", "regex", "^mac_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(encoded_exec)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Log or History Clearing",
    description: "A command deletes or truncates logs or shell history, or disables history",
    severity: "high",
    logic: "AND",
    tags: ["defense-evasion", "anti-forensics", "macos"],
    conditions: [
      cond("category", "regex", "^mac_(?!fsevent)", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(log_clearing)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Attack or Reconnaissance Tool Used",
    description: "A command line names a known attack, C2 or privilege-escalation tool",
    severity: "high",
    logic: "AND",
    tags: ["discovery", "execution", "macos"],
    conditions: [
      cond("category", "regex", "^mac_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(attack_tool|recon)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Quarantine Attribute Removed",
    description: "A command strips com.apple.quarantine (xattr -d / -c), which stops Gatekeeper from checking a downloaded file",
    severity: "medium",
    logic: "AND",
    tags: ["defense-evasion", "macos"],
    conditions: [
      cond("category", "regex", "^mac_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(quarantine_removal)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Security Control Disabled by Command",
    description: "A command turns off Gatekeeper, SIP, the firewall, FileVault, the quarantine or TCC (spctl --master-disable, csrutil disable, tccutil reset, ...)",
    severity: "high",
    logic: "AND",
    tags: ["defense-evasion", "impair-defenses", "macos"],
    conditions: [
      cond("category", "regex", "^mac_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(security_disable)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Fake Password Prompt",
    description: "An AppleScript dialog asks for a password (display dialog ... hidden answer) — how macOS stealers collect the login password",
    severity: "critical",
    logic: "AND",
    tags: ["credential-access", "input-capture", "macos"],
    conditions: [
      cond("category", "regex", "^mac_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(fake_password_prompt)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Keychain Access From the Command Line",
    description: "A command reads or dumps keychain secrets (security find-generic-password / dump-keychain, chainbreaker)",
    severity: "high",
    logic: "AND",
    tags: ["credential-access", "macos"],
    conditions: [
      cond("category", "regex", "^mac_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(keychain_access)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Account Created or Made Admin From the Command Line",
    description: "A command creates an account or adds one to the admin group (dscl . -create, sysadminctl -addUser, dseditgroup)",
    severity: "medium",
    logic: "AND",
    tags: ["persistence", "account-manipulation", "macos"],
    conditions: [
      cond("category", "regex", "^mac_", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(account_creation)\\b", "c2"),
    ],
  },
  {
    name: "macOS: AppleScript Run From a Script or Launch Item",
    description: "osascript -e or 'do shell script' in a launch item, cron job or startup file",
    severity: "medium",
    logic: "AND",
    tags: ["execution", "macos"],
    conditions: [
      cond("category", "regex", "^mac_(launch_item|cron_job|cron_script|config_line|plist_entry)$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(applescript_exec)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Launch Item Runs From a Temp or Shared Folder",
    description: "A LaunchAgent/LaunchDaemon's program lives in /tmp, /Users/Shared or /var/folders",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "macos"],
    conditions: [
      cond("category", "regex", "^mac_launch_item$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(program_in_temp)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Launch Item Runs a Script or Interpreter",
    description: "A LaunchAgent/LaunchDaemon starts a shell, Python, osascript or a script file — most legitimate launch items run a signed binary",
    severity: "medium",
    logic: "AND",
    tags: ["persistence", "execution", "macos"],
    conditions: [
      cond("category", "regex", "^mac_launch_item$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(script_program)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Launch Item Injects a Library (DYLD_*)",
    description: "A LaunchAgent/LaunchDaemon sets DYLD_INSERT_LIBRARIES or another DYLD_ variable for its program",
    severity: "critical",
    logic: "AND",
    tags: ["persistence", "defense-evasion", "hijack-execution-flow", "macos"],
    conditions: [
      cond("category", "regex", "^mac_launch_item$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(dyld_injection)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Launch Item Uses an Apple Name Outside /System",
    description: "A launch item labelled com.apple.* lives outside /System — Apple's own jobs are in /System/Library",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "masquerading", "macos"],
    conditions: [
      cond("category", "regex", "^mac_launch_item$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(apple_name_masquerade)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Hidden Launch Item",
    description: "A launch item's plist or program is a dot-file",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "defense-evasion", "macos"],
    conditions: [
      cond("category", "regex", "^mac_launch_item$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(hidden_launch_item)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Unsigned or Ad-hoc Signed Persistent or Running Program",
    description: "A launch item's program or a running executable outside the system folders has no signature or only an ad-hoc one",
    severity: "medium",
    logic: "AND",
    tags: ["persistence", "defense-evasion", "macos"],
    conditions: [
      cond("category", "regex", "^mac_(code_signature|process)$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(untrusted_signature)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Launch Item Program Missing",
    description: "A launch item points to a program that is no longer on disk — removed tooling, or a broken leftover",
    severity: "low",
    logic: "AND",
    tags: ["persistence", "macos"],
    conditions: [
      cond("category", "regex", "^mac_code_signature$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(program_missing)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Background Item Without a Developer Signature",
    description: "An enabled login/background item (Background Task Management) has no Team ID and isn't part of macOS",
    severity: "medium",
    logic: "AND",
    tags: ["persistence", "macos"],
    conditions: [
      cond("category", "regex", "^mac_background_item$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(unsigned_background_item)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Login or Background Item in a Temp or Shared Folder",
    description: "A login/background item runs from /tmp, /Users/Shared or /var/folders",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "macos"],
    conditions: [
      cond("category", "regex", "^mac_background_item$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(item_in_temp)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Login or Logout Hook",
    description: "com.apple.loginwindow has a LoginHook/LogoutHook — a script run as root at every login, deprecated and rarely legitimate",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "boot-or-logon-initialization-scripts", "macos"],
    conditions: [
      cond("category", "regex", "^mac_plist_entry$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(login_hook)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Custom emond Rule",
    description: "An emond rule other than Apple's sample — emond runs commands on events as root",
    severity: "medium",
    logic: "AND",
    tags: ["persistence", "event-triggered-execution", "macos"],
    conditions: [
      cond("category", "regex", "^mac_plist_entry$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(emond_rule)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Startup, Periodic or rc Script",
    description: "A legacy StartupItem, rc.local/launchd.conf, *.local periodic file or a non-Apple /etc/periodic script — run as root at boot or on a schedule",
    severity: "medium",
    logic: "AND",
    tags: ["persistence", "boot-or-logon-initialization-scripts", "macos"],
    conditions: [
      cond("category", "regex", "^mac_(config_line|plist_entry)$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(startup_item|boot_or_periodic_script)\\b", "c2"),
    ],
  },
  {
    name: "macOS: SSH rc Script",
    description: "~/.ssh/rc or /etc/ssh/sshrc runs on every SSH login",
    severity: "medium",
    logic: "AND",
    tags: ["persistence", "macos"],
    conditions: [
      cond("category", "regex", "^mac_config_line$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(ssh_rc)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Process Running From a Deleted Executable",
    description: "A running process's executable has been deleted from disk — common for self-deleting malware",
    severity: "high",
    logic: "AND",
    tags: ["defense-evasion", "execution", "macos"],
    conditions: [
      cond("category", "regex", "^mac_process$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(deleted_executable)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Process Executable in a Temp or Shared Folder",
    description: "A running process's executable lives in /tmp, /Users/Shared or /var/folders (App Translocation excluded)",
    severity: "high",
    logic: "AND",
    tags: ["execution", "macos"],
    conditions: [
      cond("category", "regex", "^mac_process$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(exe_in_temp)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Shell or Interpreter Holding a Network Socket",
    description: "A shell, Python, Perl, Ruby, osascript or netcat process has a network connection or listener",
    severity: "high",
    logic: "AND",
    tags: ["command-and-control", "execution", "macos"],
    conditions: [
      cond("category", "regex", "^mac_socket$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(shell_or_interpreter_socket)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Non-Standard Network Listener",
    description: "A process other than macOS's own services listens on a non-loopback address",
    severity: "low",
    logic: "AND",
    tags: ["command-and-control", "macos"],
    conditions: [
      cond("category", "regex", "^mac_socket$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(network_listener)\\b", "c2"),
    ],
  },
  {
    name: "macOS: System Integrity Protection or Sealed System Volume Disabled",
    description: "SIP or the Signed System Volume seal is off — rootkits and kernel extensions are no longer blocked",
    severity: "high",
    logic: "AND",
    tags: ["defense-evasion", "impair-defenses", "macos"],
    conditions: [
      cond("category", "regex", "^mac_security_setting$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(sip_disabled|ssv_disabled)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Gatekeeper Disabled",
    description: "Gatekeeper is off — unsigned and unnotarized apps run without a check",
    severity: "medium",
    logic: "AND",
    tags: ["defense-evasion", "impair-defenses", "macos"],
    conditions: [
      cond("category", "regex", "^mac_security_setting$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(gatekeeper_disabled)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Remote Access Service Enabled",
    description: "Remote Login (SSH), Screen Sharing, Remote Management (ARD) or Remote Apple Events is on",
    severity: "low",
    logic: "AND",
    tags: ["lateral-movement", "initial-access", "macos"],
    conditions: [
      cond("category", "regex", "^mac_security_setting$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(remote_login_on|screen_sharing_on|remote_management_on|remote_apple_events_on)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Firewall or FileVault Off, or Automatic Login",
    description: "The application firewall or FileVault is off, or the Mac logs a user in automatically",
    severity: "low",
    logic: "AND",
    tags: ["defense-evasion", "macos"],
    conditions: [
      cond("category", "regex", "^mac_(security_setting|plist_entry)$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(firewall_off|filevault_off|auto_login)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Sensitive Privacy Permission Granted to a Non-Apple Program",
    description: "TCC grants Full Disk Access, Accessibility, Screen Recording, Input Monitoring, Automation, camera or microphone to a non-Apple client — review the client",
    severity: "low",
    logic: "AND",
    tags: ["collection", "privilege-escalation", "macos"],
    conditions: [
      cond("category", "regex", "^mac_tcc_grant$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(sensitive_grant)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Privacy Permission Granted to a Bare Binary",
    description: "TCC grants a sensitive permission to a binary path rather than an app bundle — typical of planted tooling",
    severity: "high",
    logic: "AND",
    tags: ["collection", "privilege-escalation", "macos"],
    conditions: [
      cond("category", "regex", "^mac_tcc_grant$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(binary_path_client|client_in_temp)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Download From a Raw IP Address",
    description: "LaunchServices recorded a download from a bare IP address",
    severity: "medium",
    logic: "AND",
    tags: ["initial-access", "ingress-tool-transfer", "macos"],
    conditions: [
      cond("category", "regex", "^mac_quarantine_event$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(download_from_ip)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Non-Standard Login Authorization Plugin",
    description: "system.login.console runs an authorization mechanism that isn't Apple's — it sees the password at every login",
    severity: "high",
    logic: "AND",
    tags: ["credential-access", "persistence", "macos"],
    conditions: [
      cond("category", "regex", "^mac_auth_mechanism$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(non_standard_auth_mechanism)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Non-Apple Kernel Extension Loaded",
    description: "A third-party kernel extension is loaded",
    severity: "medium",
    logic: "AND",
    tags: ["persistence", "rootkit", "macos"],
    conditions: [
      cond("category", "regex", "^mac_kext$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(non_apple_kext)\\b", "c2"),
    ],
  },
  {
    name: "macOS: System Proxy Configured",
    description: "An HTTP/HTTPS/SOCKS proxy or proxy auto-config is set — adware and traffic interception set these",
    severity: "medium",
    logic: "AND",
    tags: ["collection", "adversary-in-the-middle", "macos"],
    conditions: [
      cond("category", "regex", "^mac_proxy$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(proxy_configured)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Application From an Unknown Source",
    description: "An installed app is neither from the App Store, Apple, nor an identified developer",
    severity: "low",
    logic: "AND",
    tags: ["execution", "macos"],
    conditions: [
      cond("category", "regex", "^mac_application$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(unknown_source_app)\\b", "c2"),
    ],
  },
  {
    name: "macOS: XProtect Behavioural Detection",
    description: "XProtect's behavioural engine recorded an event (XPdb) — review what it saw",
    severity: "medium",
    logic: "AND",
    tags: ["execution", "macos"],
    conditions: [
      cond("category", "regex", "^mac_xprotect_event$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(xprotect_event)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Persistence Location Changed (FSEvents)",
    description: "FSEvents recorded a file created, renamed or modified in a launch item, startup, cron, SSH, TCC or account location",
    severity: "low",
    logic: "AND",
    tags: ["persistence", "macos"],
    conditions: [
      cond("category", "regex", "^mac_fsevent$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(persistence_path_change)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Log or History File Deleted (FSEvents)",
    description: "FSEvents recorded the deletion of a log, audit trail or shell history file",
    severity: "medium",
    logic: "AND",
    tags: ["defense-evasion", "anti-forensics", "macos"],
    conditions: [
      cond("category", "regex", "^mac_fsevent$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(log_or_history_deleted)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Executable Dropped in Downloads, Desktop or a Temp Folder (FSEvents)",
    description: "FSEvents recorded a script, package, disk image, app or library created in Downloads, Desktop or a temp/shared folder",
    severity: "low",
    logic: "AND",
    tags: ["execution", "ingress-tool-transfer", "macos"],
    conditions: [
      cond("category", "regex", "^mac_fsevent$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(executable_created_in_user_or_temp)\\b", "c2"),
    ],
  },
  {
    name: "macOS: SSH Key With a Forced Command or Environment",
    description: "An authorized_keys entry runs a forced command or sets environment variables",
    severity: "medium",
    logic: "AND",
    tags: ["persistence", "macos"],
    conditions: [
      cond("category", "regex", "^mac_ssh_authorized_key$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(forced_command|environment_option)\\b", "c2"),
    ],
  },
  {
    name: "macOS: authorized_keys in an Unusual Location",
    description: "An authorized_keys file outside a home folder",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "macos"],
    conditions: [
      cond("category", "regex", "^mac_ssh_authorized_key$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(unusual_location)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Broad sudo Grant",
    description: "A sudoers entry grants ALL to a non-default user, or weakens sudo (!authenticate, LD_PRELOAD kept)",
    severity: "medium",
    logic: "AND",
    tags: ["privilege-escalation", "macos"],
    conditions: [
      cond("category", "regex", "^mac_sudoers$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(full_root_grant|weakened_sudo)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Scheduled Job or Startup File Uses a Temp Folder",
    description: "A cron/at job, launch item or startup file refers to /tmp, /Users/Shared or /var/tmp",
    severity: "high",
    logic: "AND",
    tags: ["persistence", "macos"],
    conditions: [
      cond("category", "regex", "^mac_(cron_job|cron_script|launch_item|config_line)$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(mentions_temp_path)\\b", "c2"),
    ],
  },
  {
    name: "macOS: SUID File in a Temp or Home Folder",
    description: "A setuid/setgid file in a temp or home folder",
    severity: "high",
    logic: "AND",
    tags: ["privilege-escalation", "persistence", "macos"],
    conditions: [
      cond("category", "regex", "^mac_fs_entry$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(suid_in_user_or_temp_dir)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Hidden File in a Temp Folder",
    description: "A dot-file or deceptively named file in a temp folder",
    severity: "medium",
    logic: "AND",
    tags: ["defense-evasion", "macos"],
    conditions: [
      cond("category", "regex", "^mac_fs_entry$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(hidden_file_in_temp|deceptive_name)\\b", "c2"),
    ],
  },
  {
    name: "macOS: Weak SSH Server Setting",
    description: "sshd allows root login with a password, empty passwords, password authentication or an AuthorizedKeysCommand",
    severity: "low",
    logic: "AND",
    tags: ["initial-access", "macos"],
    conditions: [
      cond("category", "regex", "^mac_config_line$", "c1"),
      cond("summary", "regex", "findings=[^;]*\\b(weak_sshd_setting)\\b", "c2"),
    ],
  },
];

export interface SeedResult {
  seeded: string[];
  errors: { name: string; error: string }[];
}

/**
 * Brings the `isBuiltin: true` rules in line with BUILTIN_RULES: each rule is
 * updated in place by name (so its id — and every finding linked to it —
 * survives), new ones are created, and built-ins no longer shipped are
 * removed (their findings keep their own title/severity; ruleId becomes
 * null). Each rule's `enabled` state is preserved.
 */
export async function seedBuiltinWinArtifactRules(): Promise<SeedResult> {
  const seeded: string[] = [];
  const errors: { name: string; error: string }[] = [];

  const existing = await prisma.windowsArtifactRule.findMany({
    where:  { isBuiltin: true },
    select: { id: true, name: true },
    orderBy: { createdAt: "asc" },
  });
  const idByName = new Map<string, string>();
  const duplicates: string[] = [];
  for (const r of existing) {
    if (idByName.has(r.name)) duplicates.push(r.id);
    else idByName.set(r.name, r.id);
  }

  for (const def of BUILTIN_RULES) {
    try {
      const data = {
        description: def.description,
        severity:    def.severity,
        logic:       def.logic,
        conditions:  def.conditions as unknown as Prisma.InputJsonValue,
        tags:        def.tags,
      };
      const id = idByName.get(def.name);
      if (id) {
        await prisma.windowsArtifactRule.update({ where: { id }, data });
      } else {
        await prisma.windowsArtifactRule.create({ data: { ...data, name: def.name, enabled: true, isBuiltin: true } });
      }
      seeded.push(def.name);
    } catch (err) {
      errors.push({ name: def.name, error: String(err) });
    }
  }

  const shipped = new Set(BUILTIN_RULES.map((d) => d.name));
  const retired = existing.filter((r) => !shipped.has(r.name)).map((r) => r.id);
  if (retired.length > 0 || duplicates.length > 0) {
    await prisma.windowsArtifactRule.deleteMany({ where: { id: { in: [...retired, ...duplicates] } } });
  }

  return { seeded, errors };
}
