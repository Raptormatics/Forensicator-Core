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
 */

const TYPE_BASE_CONFIDENCE: Record<string, number> = {
  shared_host:         90,
  shared_user:         80,
  shared_hash:         85,
  shared_ip:           70,
  shared_domain:       65,
  shared_url:          60,
  shared_process:      55,
  shared_account:      75,
  shared_finding_type: 50,
  shared_category:     40,
};

type Group = { invIds: Set<string>; hosts: Set<string>; evidenceIds: Set<string> };

function addToGroup(map: Map<string, Group>, key: string, invId: string, hostname: string, evidenceId?: string) {
  if (!map.has(key)) map.set(key, { invIds: new Set(), hosts: new Set(), evidenceIds: new Set() });
  const g = map.get(key)!;
  g.invIds.add(invId);
  g.hosts.add(hostname);
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

  // ── 1. Shared hostname ──────────────────────────────────────────────────
  const hostnameGroups = new Map<string, Group>();
  for (const inv of investigations) {
    if (inv.hostname) addToGroup(hostnameGroups, inv.hostname, inv.id, inv.hostname);
  }

  // ── 2. Shared username ──────────────────────────────────────────────────
  const usernameGroups = new Map<string, Group>();
  for (const inv of investigations) {
    if (inv.username) addToGroup(usernameGroups, inv.username, inv.id, hostMap[inv.id]);
  }

  // ── 3. Shared finding types (same attack technique) ─────────────────────
  const findings = await prisma.finding.findMany({
    where: { investigationId: { in: invIds } },
    select: { investigationId: true, findingType: true, category: true },
  });
  const findingTypeGroups = new Map<string, Group>();
  const categoryGroups    = new Map<string, Group>();
  for (const f of findings) {
    const host = hostMap[f.investigationId];
    addToGroup(findingTypeGroups, f.findingType, f.investigationId, host);
    addToGroup(categoryGroups,    f.category,    f.investigationId, host);
  }

  // ── 4. Shared evidence IOC values ───────────────────────────────────────
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
    const host = hostMap[e.investigationId];
    if (e.domain)      addToGroup(domainGroups,      e.domain,      e.investigationId, host, e.id);
    if (e.ip)          addToGroup(ipGroups,           e.ip,          e.investigationId, host, e.id);
    if (e.hash)        addToGroup(hashGroups,         e.hash,        e.investigationId, host, e.id);
    if (e.url)         addToGroup(urlGroups,          e.url,         e.investigationId, host, e.id);
    if (e.processName) addToGroup(processNameGroups,  e.processName, e.investigationId, host, e.id);
    if (e.username)    addToGroup(evUsernameGroups,   e.username,    e.investigationId, host, e.id);
  }

  // ── Build correlations ──────────────────────────────────────────────────
  const newCorrelations: {
    caseId: string; correlationType: string; value: string;
    hosts: string[]; investigationIds: string[]; evidenceIds: string[];
  }[] = [];

  function pushIfMulti(map: Map<string, Group>, type: string) {
    for (const [value, group] of map) {
      if (group.invIds.size >= 2) {
        newCorrelations.push({
          caseId,
          correlationType: type,
          value,
          hosts: Array.from(group.hosts),
          investigationIds: Array.from(group.invIds),
          evidenceIds: Array.from(group.evidenceIds),
        });
      }
    }
  }

  pushIfMulti(hostnameGroups,    "shared_host");
  pushIfMulti(usernameGroups,    "shared_user");
  pushIfMulti(hashGroups,        "shared_hash");
  pushIfMulti(ipGroups,          "shared_ip");
  pushIfMulti(domainGroups,      "shared_domain");
  pushIfMulti(urlGroups,         "shared_url");
  pushIfMulti(processNameGroups, "shared_process");
  pushIfMulti(evUsernameGroups,  "shared_account");
  pushIfMulti(findingTypeGroups, "shared_finding_type");
  pushIfMulti(categoryGroups,    "shared_category");

  // Deduplicate within this run — keep the larger investigation set per (type, value)
  const seen = new Map<string, number>();
  const deduped = newCorrelations.filter((c) => {
    const key = `${c.correlationType}::${c.value}`;
    const size = c.investigationIds.length;
    const prevSize = seen.get(key);
    if (prevSize !== undefined && prevSize >= size) return false;
    seen.set(key, size);
    return true;
  });

  function confidenceFor(type: string, invCount: number): number {
    return Math.min(100, (TYPE_BASE_CONFIDENCE[type] ?? 50) + invCount * 10);
  }

  let created = 0;
  for (const corr of deduped) {
    const existing = await prisma.correlation.findFirst({
      where: { caseId, correlationType: corr.correlationType, value: corr.value },
    });
    if (existing) {
      const mergedInvIds      = Array.from(new Set([...existing.investigationIds, ...corr.investigationIds]));
      const mergedHosts       = Array.from(new Set([...existing.hosts, ...corr.hosts]));
      const mergedEvidenceIds = Array.from(new Set([...existing.evidenceIds, ...corr.evidenceIds]));
      await prisma.correlation.update({
        where: { id: existing.id },
        data: {
          confidence: confidenceFor(corr.correlationType, mergedInvIds.length),
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
          confidence: confidenceFor(corr.correlationType, corr.investigationIds.length),
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
