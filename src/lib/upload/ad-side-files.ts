/**
 * Domain-controller side files the collector writes next to its
 * investigation\ad\*-finding.json files — CSV inventories, raw event JSON,
 * and repadmin text — which the finding-JSON intake in zip.ts would
 * otherwise drop silently (they aren't *-finding.json). Each known file is
 * converted into one synthetic finding in the same shape the collector
 * emits, so it flows through the normal finding → evidence → timeline
 * pipeline (SHA-256 columns become hash evidence, timestamps become
 * timeline entries, etc.).
 *
 * Severity is escalated only on concrete, well-understood signals:
 *   - gpp-cpassword-findings.csv with any row (GPP cpassword = recoverable
 *     credential, T1552.006)
 *   - 4662 events whose properties include a DCSync replication right
 *   - AD CS templates shaped like ESC1 (enrollee supplies subject +
 *     authentication EKU + no manager approval)
 *   - write-type ACEs on GPOs / critical objects held by principals outside
 *     the built-in privileged set
 * Everything else is Informational inventory.
 */
import type { JsonObject } from "@/types/json";
import type { ParsedUploadFinding } from "@/types/findings";
import { normalizeParsedFinding, findingSchema } from "@/lib/schemas/finding";

type Severity = "Important" | "Notable" | "Interesting" | "Informational";

interface SideFileSpec {
  findingType: string;
  category: string;
  description: string;
  mitre?: { technique_id: string; technique: string; tactic: string }[];
  /** Turn the parsed rows into evidence rows + a severity. */
  evaluate: (rows: JsonObject[]) => { evidence: JsonObject[]; severity: Severity; reason: string };
}

const EVIDENCE_CAP = 5000;

// ── Helpers ─────────────────────────────────────────────────────────────────

/** RFC 4180 CSV (what PowerShell's Export-Csv writes: every field quoted,
 * "" escapes, CRLF rows, optional BOM) → array of header-keyed objects. */
export function parseCsv(text: string): JsonObject[] {
  const src = text.replace(/^﻿/, "");
  const rows: string[][] = [];
  let field = "";
  let row: string[] = [];
  let inQuotes = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (inQuotes) {
      if (ch === '"') {
        if (src[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += ch;
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field); field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && src[i + 1] === "\n") i++;
      row.push(field); field = "";
      if (row.some((c) => c !== "")) rows.push(row);
      row = [];
    } else field += ch;
  }
  if (field !== "" || row.length > 0) { row.push(field); if (row.some((c) => c !== "")) rows.push(row); }
  if (rows.length === 0) return [];
  const [header, ...body] = rows;
  return body.map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ""])) as JsonObject);
}

function parseJsonRows(text: string): JsonObject[] {
  const parsed = JSON.parse(text.replace(/^﻿/, "")) as unknown;
  const arr = Array.isArray(parsed) ? parsed : [parsed];
  return arr.filter((r): r is JsonObject => !!r && typeof r === "object" && !Array.isArray(r));
}

function s(v: unknown): string {
  return v == null ? "" : String(v);
}

const PRIVILEGED_PRINCIPALS = [
  "domain admins", "enterprise admins", "schema admins", "administrators", "nt authority\\system", "system",
  "creator owner", "enterprise domain controllers", "domain controllers", "group policy creator owners",
  "enterprise key admins", "key admins", "cert publishers", "nt authority\\enterprise domain controllers", "builtin\\administrators",
];
const WRITE_RIGHTS_RE = /GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|FullControl|Modify|Write\b|ChangePermissions|TakeOwnership/i;

function isPrivilegedPrincipal(principal: string): boolean {
  const p = principal.toLowerCase();
  return PRIVILEGED_PRINCIPALS.some((x) => p === x || p.endsWith(`\\${x}`));
}

function flagAclRows(rows: JsonObject[]): { evidence: JsonObject[]; flagged: number } {
  let flagged = 0;
  const evidence = rows.map((r) => {
    const suspicious = WRITE_RIGHTS_RE.test(s(r.Rights)) && !isPrivilegedPrincipal(s(r.Principal));
    if (suspicious) flagged++;
    return { ...r, triage_candidate: suspicious } as JsonObject;
  });
  return { evidence, flagged };
}

// DS-Replication-Get-Changes / -All / -In-Filtered-Set — the rights a
// DCSync uses; Windows logs them as {GUID} in a 4662 event's Properties.
const DCSYNC_GUIDS = [
  "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
  "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
  "89e95b76-444d-4c62-991a-0facbeda640c",
];

function eventData(xml: string, name: string): string | null {
  const m = xml.match(new RegExp(`<Data Name=['"]${name}['"]>([^<]*)</Data>`, "i"));
  return m ? m[1] : null;
}

// msPKI-Certificate-Name-Flag CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
// msPKI-Enrollment-Flag CT_FLAG_PEND_ALL_REQUESTS (manager approval).
const ENROLLEE_SUPPLIES_SUBJECT = 0x1;
const PEND_ALL_REQUESTS = 0x2;
const AUTH_EKUS = ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.4", "2.5.29.37.0"];

function intFlag(v: unknown): number {
  const n = Number.parseInt(s(v), 10);
  return Number.isNaN(n) ? 0 : n;
}

// ── Known side files ──────────────────────────────────────────────────────

const inventory = (findingType: string, category: string, description: string): SideFileSpec => ({
  findingType, category, description,
  evaluate: (rows) => ({ evidence: rows, severity: "Informational", reason: `${rows.length} inventory record(s)` }),
});

const SIDE_FILES: Record<string, SideFileSpec> = {
  "gpo-inventory.csv": inventory("AD GPO Inventory", "Discovery", "Group Policy objects with AD vs. SYSVOL (GPT) version comparison."),
  "trust-inventory.csv": inventory("AD Trust Inventory", "Discovery", "Domain and forest trusts visible from this DC."),
  "dns-zone-inventory.csv": inventory("AD DNS Zone Inventory", "Discovery", "DNS zones hosted on this DC."),
  "adcs-authorities.csv": inventory("AD CS Certificate Authorities", "Discovery", "Enterprise certification authorities published in AD."),
  "sysvol-file-inventory.csv": {
    findingType: "SYSVOL File Inventory",
    category: "Persistence",
    description: "Recursive SYSVOL policy/script file inventory with SHA-256 (hashes are checked against threat intel as evidence).",
    mitre: [{ technique_id: "T1484.001", technique: "Domain Policy Modification: Group Policy Modification", tactic: "defense-evasion" }],
    evaluate: (rows) => ({
      evidence: rows.map((r) => ({ ...r, sha256: s(r.SHA256 ?? r.Sha256 ?? r.Hash) || undefined, file_path: s(r.Path ?? r.FullName) || undefined }) as JsonObject),
      severity: "Informational",
      reason: `${rows.length} SYSVOL file(s) inventoried`,
    }),
  },
  "gpp-cpassword-findings.csv": {
    findingType: "Group Policy Preferences cpassword",
    category: "Credential Access",
    description: "SYSVOL Group Policy Preferences XML containing a cpassword attribute — the AES key is public, so the stored credential is recoverable by any domain user (the collector does not record the value).",
    mitre: [{ technique_id: "T1552.006", technique: "Unsecured Credentials: Group Policy Preferences", tactic: "credential-access" }],
    evaluate: (rows) => ({
      evidence: rows,
      severity: rows.length > 0 ? "Important" : "Informational",
      reason: rows.length > 0 ? `${rows.length} GPP file(s) with a recoverable cpassword` : "No cpassword found",
    }),
  },
  "gpo-write-acl-review.csv": {
    findingType: "GPO Write ACL Review",
    category: "Privilege Escalation",
    description: "Write-type permissions on GPO SYSVOL folders. Rows held by principals outside the built-in privileged groups are marked triage_candidate.",
    mitre: [{ technique_id: "T1484.001", technique: "Domain Policy Modification: Group Policy Modification", tactic: "privilege-escalation" }],
    evaluate: (rows) => {
      const { evidence, flagged } = flagAclRows(rows);
      return { evidence, severity: flagged > 0 ? "Notable" : "Informational", reason: `${flagged} write ACE(s) held by non-privileged principals` };
    },
  },
  "critical-object-acl-review.csv": {
    findingType: "Critical AD Object Write ACL Review",
    category: "Privilege Escalation",
    description: "Write-type ACEs on the domain root, AdminSDHolder, Domain Controllers OU and AD CS templates. Rows held by principals outside the built-in privileged groups are marked triage_candidate.",
    mitre: [{ technique_id: "T1222.001", technique: "File and Directory Permissions Modification: Windows", tactic: "defense-evasion" }],
    evaluate: (rows) => {
      const { evidence, flagged } = flagAclRows(rows);
      return { evidence, severity: flagged > 0 ? "Notable" : "Informational", reason: `${flagged} write ACE(s) held by non-privileged principals` };
    },
  },
  "adcs-templates.csv": {
    findingType: "AD CS Certificate Templates",
    category: "Privilege Escalation",
    description: "Certificate template configuration. Templates where the enrollee supplies the subject, an authentication EKU is present (or any purpose), and manager approval is off are marked esc1_shaped — confirm enrollment rights before treating as exploitable.",
    mitre: [{ technique_id: "T1649", technique: "Steal or Forge Authentication Certificates", tactic: "credential-access" }],
    evaluate: (rows) => {
      let esc1 = 0;
      const evidence = rows.map((r) => {
        const ekus = s(r.EKUs).split(";").map((e) => e.trim()).filter(Boolean);
        const shaped = (intFlag(r.NameFlags) & ENROLLEE_SUPPLIES_SUBJECT) !== 0
          && (intFlag(r.EnrollmentFlags) & PEND_ALL_REQUESTS) === 0
          && (ekus.length === 0 || ekus.some((e) => AUTH_EKUS.includes(e)));
        if (shaped) esc1++;
        return { ...r, esc1_shaped: shaped } as JsonObject;
      });
      return { evidence, severity: esc1 > 0 ? "Notable" : "Informational", reason: `${esc1} ESC1-shaped template(s)` };
    },
  },
  "directory-service-access-4662.json": {
    findingType: "Directory Service Access Events (4662)",
    category: "Credential Access",
    description: "Event 4662 (an operation was performed on an AD object), as generated by configured SACLs. Events whose properties include a directory replication right are marked dcsync_right — from a non-DC account this is DCSync.",
    mitre: [{ technique_id: "T1003.006", technique: "OS Credential Dumping: DCSync", tactic: "credential-access" }],
    evaluate: (rows) => {
      let dcsync = 0;
      const evidence = rows.slice(0, EVIDENCE_CAP).map((r) => {
        const xml = s(r.Xml);
        const props = (eventData(xml, "Properties") ?? "").toLowerCase();
        const subject = eventData(xml, "SubjectUserName");
        const hit = DCSYNC_GUIDS.some((g) => props.includes(g));
        // Machine accounts (DCs replicating with each other) end in "$".
        if (hit && subject && !subject.endsWith("$")) dcsync++;
        return {
          time: s(r.Time), event_id: s(r.EventId), record_id: s(r.RecordId),
          username: subject, subject_domain: eventData(xml, "SubjectDomainName"),
          object_name: eventData(xml, "ObjectName"), object_type: eventData(xml, "ObjectType"),
          access_mask: eventData(xml, "AccessMask"), properties: props, dcsync_right: hit,
        } as JsonObject;
      });
      return {
        evidence,
        severity: dcsync > 0 ? "Important" : "Informational",
        reason: dcsync > 0 ? `${dcsync} replication-right access(es) by non-machine accounts` : `${rows.length} 4662 event(s), none with replication rights from user accounts`,
      };
    },
  },
  "adcs-audit-events.json": {
    findingType: "AD CS Certificate Request Audit Events",
    category: "Credential Access",
    description: "Certificate Services request (4886), issuance (4887) and denial (4888) events from this CA's Security log.",
    mitre: [{ technique_id: "T1649", technique: "Steal or Forge Authentication Certificates", tactic: "credential-access" }],
    evaluate: (rows) => ({
      evidence: rows.slice(0, EVIDENCE_CAP).map((r) => {
        const xml = s(r.Xml);
        return {
          time: s(r.Time), event_id: s(r.EventId), record_id: s(r.RecordId),
          requester: eventData(xml, "Requester"), request_id: eventData(xml, "RequestId"),
          attributes: eventData(xml, "Attributes"), disposition: eventData(xml, "Disposition"),
          subject: eventData(xml, "Subject"),
        } as JsonObject;
      }),
      severity: "Informational",
      reason: `${rows.length} certificate request event(s)`,
    }),
  },
  "replication-health.txt": {
    findingType: "AD Replication Health (repadmin)",
    category: "Discovery",
    description: "repadmin replication summary/status output from this DC, one evidence row per line.",
    evaluate: (rows) => {
      const failing = rows.filter((r) => /\b(fail(ed|ure)?|error|denied)\b/i.test(s(r.line)) && !/\b0 failures?\b/i.test(s(r.line))).length;
      return {
        evidence: rows,
        severity: failing > 0 ? "Interesting" : "Informational",
        reason: failing > 0 ? `${failing} line(s) report replication failures/errors` : "No replication errors reported",
      };
    },
  },
};

export function isAdSideFile(normalizedPath: string): boolean {
  const parts = normalizedPath.toLowerCase().split("/");
  const name = parts[parts.length - 1];
  return parts[parts.length - 2] === "ad" && name in SIDE_FILES;
}

/** Converts one recognized ad\<file> into a finding, or throws on unreadable content. */
export function convertAdSideFile(normalizedPath: string, content: string, host: JsonObject | undefined): ParsedUploadFinding {
  const name = normalizedPath.toLowerCase().split("/").pop()!;
  const spec = SIDE_FILES[name];
  const rows: JsonObject[] = name.endsWith(".csv")
    ? parseCsv(content)
    : name.endsWith(".json")
      ? parseJsonRows(content)
      : content.replace(/^﻿/, "").split(/\r?\n/).map((line) => line.trimEnd()).filter(Boolean).map((line) => ({ line }) as JsonObject);

  const { evidence, severity, reason } = spec.evaluate(rows);
  const raw = findingSchema.parse({
    finding_id: `ad-${name.replace(/[^a-z0-9]+/g, "-")}`,
    finding_type: spec.findingType,
    category: spec.category,
    severity,
    host,
    source: { artifact: name, collector: "Forensicator", converted_by: "Forensicator Core (ad side file)" },
    summary: { title: spec.findingType, description: spec.description },
    risk: { reason },
    mitre: spec.mitre ?? [],
    evidence: evidence.slice(0, EVIDENCE_CAP),
    metadata: { evidence_total: evidence.length, evidence_truncated: evidence.length > EVIDENCE_CAP },
    findingtags: ["active-directory"],
  });
  return { path: normalizedPath, sourceCategory: "ad", data: normalizeParsedFinding(raw, "ad") };
}
