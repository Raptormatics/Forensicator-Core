import { prisma } from "@/lib/db/prisma";

/**
 * Cross-investigation correlation engine. Runs on every investigation
 * linked to a given Case (Intelligence -> Correlations: analysts pick a
 * case, not individual investigations — since every investigation already
 * belongs to a case, correlation is derived from the case's membership).
 * Correlations persist with that caseId; re-running for the same case (e.g.
 * after new investigations are linked) unions the investigation/host/
 * evidence lists into the existing record rather than overwriting it, so
 * repeated runs accumulate evidence instead of losing it. A different case
 * producing the same (type, value) pair gets its own separate record.
 *
 * A relationship needs the value on at least two different HOSTS, not two
 * investigations: collecting the same machine twice is the same subject, not
 * a link between two. Values are compared in canonical form (see
 * canonicalValue) so formatting differences between sources don't hide a
 * real link.
 */

const TYPE_BASE_CONFIDENCE: Record<string, number> = {
  shared_hash:         85,
  shared_ip:           70,
  shared_domain:       65,
  shared_url:          60,
  shared_process:      55,
  shared_account:      75,
  shared_finding_type: 50,
  shared_category:     40,
};

/**
 * Canonical form used for grouping and storage. Hashes, domains, IPs,
 * process names and account names are compared case-insensitively (the same
 * hash in upper case from one tool and lower case from another is the same
 * file; Windows names are case-insensitive); domains also lose a trailing
 * dot. URLs keep their path as-is — only scheme and host are case-folded.
 */
export function canonicalValue(type: string, raw: string): string {
  const v = raw.trim();
  if (type === "shared_url") {
    const m = v.match(/^([a-z][a-z0-9+.-]*:\/\/[^/?#]+)(.*)$/i);
    return m ? m[1].toLowerCase() + m[2] : v;
  }
  if (type === "shared_finding_type" || type === "shared_category") return v;
  return v.toLowerCase().replace(/\.$/, "");
}

/** Short, case-folded host name: "WS-01.corp.local" and "ws-01" are one machine. */
function hostKey(hostname: string | null, fallback: string): string {
  return hostname ? hostname.trim().toLowerCase().split(".")[0] : fallback;
}

type Group = { invIds: Set<string>; hosts: Set<string>; hostKeys: Set<string>; evidenceIds: Set<string>; rawValues: Set<string> };

function addToGroup(map: Map<string, Group>, key: string, rawValue: string, invId: string, hostname: string, hostKeyValue: string, evidenceId?: string) {
  if (!map.has(key)) map.set(key, { invIds: new Set(), hosts: new Set(), hostKeys: new Set(), evidenceIds: new Set(), rawValues: new Set() });
  const g = map.get(key)!;
  g.invIds.add(invId);
  g.hosts.add(hostname);
  g.hostKeys.add(hostKeyValue);
  g.rawValues.add(rawValue);
  if (evidenceId) g.evidenceIds.add(evidenceId);
}

export interface CorrelationRunResult {
  found: number;
  investigations: number;
}

export async function runCorrelation(investigationIds: string[], caseId: string): Promise<CorrelationRunResult> {
  const investigations = await prisma.investigation.findMany({
    where: { id: { in: investigationIds } },
    select: { id: true, hostname: true, username: true },
  });
  if (investigations.length < 2) {
    throw new Error("Need at least 2 investigations to correlate");
  }

  const invIds  = investigations.map((i) => i.id);
  const hostMap = Object.fromEntries(investigations.map((i) => [i.id, i.hostname ?? i.id]));
  const hostKeyMap = Object.fromEntries(investigations.map((i) => [i.id, hostKey(i.hostname, i.id)]));

  // Investigation.username is the account the collector ran under — on a
  // remote collection that is the responder's own account, present on every
  // host. It describes the collection, not the subject, so it is neither
  // correlated itself (no shared_user) nor counted as a shared_account.
  const collectionAccounts = new Set(
    investigations.map((i) => i.username?.trim().toLowerCase()).filter((u): u is string => !!u)
  );

  // ── 1. Shared finding types (same attack technique) ─────────────────────
  const findings = await prisma.finding.findMany({
    where: { investigationId: { in: invIds } },
    select: { investigationId: true, findingType: true, category: true },
  });
  const findingTypeGroups = new Map<string, Group>();
  const categoryGroups    = new Map<string, Group>();
  for (const f of findings) {
    const host = hostMap[f.investigationId], key = hostKeyMap[f.investigationId];
    addToGroup(findingTypeGroups, canonicalValue("shared_finding_type", f.findingType), f.findingType, f.investigationId, host, key);
    addToGroup(categoryGroups,    canonicalValue("shared_category", f.category),        f.category,    f.investigationId, host, key);
  }

  // ── 2. Shared evidence IOC values ───────────────────────────────────────
  const evidence = await prisma.evidence.findMany({
    where: {
      investigationId: { in: invIds },
      OR: [
        { domain:      { not: null } },
        { ip:          { not: null } },
        { hash:        { not: null } },
        { url:         { not: null } },
        { processName: { not: null } },
        { username:    { not: null } },
      ],
    },
    select: { id: true, investigationId: true, domain: true, ip: true, hash: true, url: true, processName: true, username: true },
  });
  const domainGroups      = new Map<string, Group>();
  const ipGroups          = new Map<string, Group>();
  const hashGroups        = new Map<string, Group>();
  const urlGroups         = new Map<string, Group>();
  const processNameGroups = new Map<string, Group>();
  const evUsernameGroups  = new Map<string, Group>();

  for (const e of evidence) {
    const host = hostMap[e.investigationId], key = hostKeyMap[e.investigationId];
    const add = (map: Map<string, Group>, type: string, raw: string) =>
      addToGroup(map, canonicalValue(type, raw), raw, e.investigationId, host, key, e.id);
    if (e.domain)      add(domainGroups,      "shared_domain",  e.domain);
    if (e.ip)          add(ipGroups,          "shared_ip",      e.ip);
    if (e.hash)        add(hashGroups,        "shared_hash",    e.hash);
    if (e.url)         add(urlGroups,         "shared_url",     e.url);
    if (e.processName) add(processNameGroups, "shared_process", e.processName);
    if (e.username && !collectionAccounts.has(e.username.trim().toLowerCase())) {
      add(evUsernameGroups, "shared_account", e.username);
    }
  }

  // ── Build correlations ──────────────────────────────────────────────────
  const newCorrelations: {
    caseId: string; correlationType: string; value: string; rawValues: string[];
    hosts: string[]; hostCount: number; investigationIds: string[]; evidenceIds: string[];
  }[] = [];

  function pushIfMulti(map: Map<string, Group>, type: string) {
    for (const [value, group] of map) {
      if (group.hostKeys.size >= 2) {
        newCorrelations.push({
          caseId,
          correlationType: type,
          value,
          rawValues: Array.from(group.rawValues),
          hosts: Array.from(group.hosts),
          hostCount: group.hostKeys.size,
          investigationIds: Array.from(group.invIds),
          evidenceIds: Array.from(group.evidenceIds),
        });
      }
    }
  }

  pushIfMulti(hashGroups,        "shared_hash");
  pushIfMulti(ipGroups,          "shared_ip");
  pushIfMulti(domainGroups,      "shared_domain");
  pushIfMulti(urlGroups,         "shared_url");
  pushIfMulti(processNameGroups, "shared_process");
  pushIfMulti(evUsernameGroups,  "shared_account");
  pushIfMulti(findingTypeGroups, "shared_finding_type");
  pushIfMulti(categoryGroups,    "shared_category");

  function confidenceFor(type: string, hostCount: number): number {
    return Math.min(100, (TYPE_BASE_CONFIDENCE[type] ?? 50) + hostCount * 10);
  }

  let created = 0;
  for (const corr of newCorrelations) {
    // Earlier runs stored values as the source spelled them; match those too
    // so a re-run merges into (and canonicalises) the existing record rather
    // than creating a duplicate next to it.
    const existing = await prisma.correlation.findFirst({
      where: { caseId, correlationType: corr.correlationType, value: { in: Array.from(new Set([corr.value, ...corr.rawValues])) } },
    });
    if (existing) {
      const mergedInvIds      = Array.from(new Set([...existing.investigationIds, ...corr.investigationIds]));
      const mergedHosts       = Array.from(new Set([...existing.hosts, ...corr.hosts]));
      const mergedEvidenceIds = Array.from(new Set([...existing.evidenceIds, ...corr.evidenceIds]));
      const mergedHostCount   = new Set(mergedHosts.map((h) => hostKey(h, h))).size;
      await prisma.correlation.update({
        where: { id: existing.id },
        data: {
          value: corr.value,
          confidence: confidenceFor(corr.correlationType, mergedHostCount),
          hosts: mergedHosts,
          investigationIds: mergedInvIds,
          evidenceIds: mergedEvidenceIds,
        },
      });
    } else {
      await prisma.correlation.create({
        data: {
          caseId: corr.caseId,
          correlationType: corr.correlationType,
          value: corr.value,
          confidence: confidenceFor(corr.correlationType, corr.hostCount),
          hosts: corr.hosts,
          investigationIds: corr.investigationIds,
          evidenceIds: corr.evidenceIds,
        },
      });
    }
    created++;
  }

  return { found: created, investigations: invIds.length };
}
