// Built-in Playbook Seed — inserts the bundled starter incident-response
// checklists into the database.
//
// Called from /api/playbooks/seed (admin only). Mirrors
// log-analysis/rule-engine/seed.ts's delete-all-then-recreate pattern for
// isBuiltin rows. These are the only playbooks Core ships — authoring
// custom playbooks stays an Enterprise-only capability, see
// src/prisma/schema/playbooks.prisma.

import { prisma } from "@/lib/db/prisma";

type TaskPriority = "critical" | "high" | "medium" | "low";

interface BuiltinTaskDef {
  title: string;
  notes?: string;
  priority: TaskPriority;
}

interface BuiltinPlaybookDef {
  name: string;
  incidentType: string;
  description: string;
  tasks: BuiltinTaskDef[];
}

export const BUILTIN_PLAYBOOKS: BuiltinPlaybookDef[] = [
  {
    name: "Ransomware",
    incidentType: "ransomware",
    description: "Initial triage and containment checklist for a suspected or confirmed ransomware event.",
    tasks: [
      { title: "Isolate affected hosts from the network", priority: "critical", notes: "Disconnect from network shares and VPN; do not power off (preserve volatile memory for RAM analysis)." },
      { title: "Identify patient zero and initial access vector", priority: "critical" },
      { title: "Capture RAM image from affected hosts before remediation", priority: "critical" },
      { title: "Identify ransomware family / variant from ransom note and encrypted file extensions", priority: "high" },
      { title: "Check for data exfiltration prior to encryption", priority: "high" },
      { title: "Determine blast radius — list all encrypted hosts/shares", priority: "high" },
      { title: "Check backups for integrity and ransomware-free restore point", priority: "high" },
      { title: "Notify legal/compliance and determine breach notification obligations", priority: "medium" },
    ],
  },
  {
    name: "Business Email Compromise",
    incidentType: "bec",
    description: "Checklist for a compromised mailbox or fraudulent wire-transfer email incident.",
    tasks: [
      { title: "Reset compromised account credentials and revoke active sessions/tokens", priority: "critical" },
      { title: "Review mailbox rules, forwarding rules, and delegate access for attacker-added entries", priority: "critical" },
      { title: "Identify sign-in source IPs/geolocations for the compromise window", priority: "high" },
      { title: "Determine if any fraudulent wire transfer instructions were sent or acted on", priority: "critical" },
      { title: "Notify finance/AP team to hold any pending transfers matching attacker patterns", priority: "high" },
      { title: "Search mailbox for sent items during the compromise window", priority: "medium" },
      { title: "Check for lateral phishing sent to other internal/external contacts", priority: "medium" },
      { title: "Enable MFA and review conditional access policies", priority: "medium" },
    ],
  },
  {
    name: "Insider Threat",
    incidentType: "insider-threat",
    description: "Checklist for a suspected malicious or negligent insider data-handling incident.",
    tasks: [
      { title: "Preserve the user's account and endpoint activity logs before access changes", priority: "critical" },
      { title: "Coordinate with HR/Legal before taking any action on the employee's account", priority: "critical" },
      { title: "Review data access, download, and file-transfer activity for the user", priority: "high" },
      { title: "Check for use of removable media, personal cloud storage, or personal email", priority: "high" },
      { title: "Review VPN/remote-access logs for off-hours or anomalous access", priority: "medium" },
      { title: "Identify any data staged for exfiltration (archives, large transfers)", priority: "high" },
      { title: "Determine scope of sensitive data potentially accessed or taken", priority: "medium" },
    ],
  },
  {
    name: "Phishing",
    incidentType: "phishing",
    description: "Checklist for a reported or detected phishing email/campaign.",
    tasks: [
      { title: "Collect the original phishing email with full headers", priority: "high" },
      { title: "Identify all recipients of the campaign across the organization", priority: "critical" },
      { title: "Determine if any recipient clicked the link or opened the attachment", priority: "critical" },
      { title: "Check for credential submission on any linked phishing page", priority: "critical" },
      { title: "Block sender domain/IP and malicious URLs at the mail gateway/proxy", priority: "high" },
      { title: "If credentials were entered, force password reset and session revocation", priority: "high" },
      { title: "Search for the malicious indicators across mail and endpoint logs org-wide", priority: "medium" },
      { title: "Notify affected users and remind staff of the campaign", priority: "low" },
    ],
  },
];

export interface SeedResult {
  seeded: string[];
  errors: { name: string; error: string }[];
}

/**
 * Wipe and recreate all `isBuiltin: true` playbooks (and their tasks) from
 * BUILTIN_PLAYBOOKS.
 */
export async function seedBuiltinPlaybooks(): Promise<SeedResult> {
  const seeded: string[] = [];
  const errors: { name: string; error: string }[] = [];

  await prisma.playbook.deleteMany({ where: { isBuiltin: true } });

  for (const def of BUILTIN_PLAYBOOKS) {
    try {
      await prisma.playbook.create({
        data: {
          name: def.name,
          incidentType: def.incidentType,
          description: def.description,
          isBuiltin: true,
          tasks: {
            create: def.tasks.map((t, i) => ({
              title: t.title,
              notes: t.notes ?? null,
              priority: t.priority,
              order: i,
            })),
          },
        },
      });
      seeded.push(def.name);
    } catch (err) {
      errors.push({ name: def.name, error: String(err) });
    }
  }

  return { seeded, errors };
}
