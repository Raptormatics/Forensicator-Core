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
 *
 * Confidence is rarity-weighted: how unusual the value is across every host
 * on record (the case's organisation), not just how many hosts in the case
 * share it. svchost.exe on three hosts and an unknown binary on the same
 * three are not equally interesting; the first is on every Windows machine.
 * Deployments with too few hosts for rarity to mean anything keep the plain
 * per-host score (see RARITY_MIN_HOSTS).
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

/** Below this many hosts on record, rarity is noise and the per-host score applies. */
export const RARITY_MIN_HOSTS = 5;

/** How many hosts on record carry the value, out of all hosts on record. */
export type Prevalence = { hosts: number; of: number };

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

const EVIDENCE_COLUMN: Record<string, "hash" | "ip" | "domain" | "url" | "processName" | "username"> = {
  shared_hash: "hash", shared_ip: "ip", shared_domain: "domain", shared_url: "url",
  shared_process: "processName", shared_account: "username",
};
const FINDING_COLUMN: Record<string, "findingType" | "category"> = {
  shared_finding_type: "findingType", shared_category: "category",
};

/**
 * Host prevalence for each candidate (type::canonical value), counted over
 * every investigation in the same organisation(s) as the case — never across
 * tenants. Uses GROUP BY (investigation, value) so common values cost one row
 * per host rather than one per evidence row.
 */
async function hostPrevalence(
  candidates: { correlationType: string; value: string; rawValues: string[] }[],
  orgIds: (string | null)[],
): Promise<{ df: Map<string, number>; N: number }> {
  const realOrgIds = orgIds.filter((o): o is string => !!o);
  const orgScope = {
    OR: [
      ...(realOrgIds.length > 0 ? [{ organizationId: { in: realOrgIds } }] : []),
      ...(orgIds.includes(null) ? [{ organizationId: null }] : []),
    ],
  };
  const scoped = await prisma.investigation.findMany({ where: orgScope, select: { id: true, hostname: true } });
  const hostOf = new Map(scoped.map((i) => [i.id, hostKey(i.hostname, i.id)]));

  const seen = new Map<string, Set<string>>();
  const note = (type: string, raw: string | null, invId: string) => {
    const host = hostOf.get(invId);
    if (!raw || !host) return;
    const key = `${type}::${canonicalValue(type, raw)}`;
    let s = seen.get(key);
    if (!s) seen.set(key, (s = new Set()));
    s.add(host);
  };

  for (const type of new Set(candidates.map((c) => c.correlationType))) {
    const ofType = candidates.filter((c) => c.correlationType === type);
    // Every spelling that canonicalises to a candidate: the case's own raw
    // spellings, the canonical form, and its trailing-dot variant; matched
    // case-insensitively so other hosts' spellings are counted too.
    const variants = Array.from(new Set(ofType.flatMap((c) => [c.value, `${c.value}.`, ...c.rawValues])));
    for (let i = 0; i < variants.length; i += 5000) {
      const chunk = variants.slice(i, i + 5000);
      const evCol = EVIDENCE_COLUMN[type];
      const fCol = FINDING_COLUMN[type];
      if (evCol) {
        const rows = await prisma.evidence.groupBy({
          by: ["investigationId", evCol],
          where: { investigation: orgScope, [evCol]: { in: chunk, mode: "insensitive" } },
        });
        for (const r of rows) note(type, r[evCol], r.investigationId);
      } else if (fCol) {
        const rows = await prisma.finding.groupBy({
          by: ["investigationId", fCol],
          where: { investigation: orgScope, [fCol]: { in: chunk } },
        });
        for (const r of rows) note(type, r[fCol], r.investigationId);
      }
    }
  }

  const df = new Map(Array.from(seen.entries()).map(([k, s]) => [k, s.size]));
  return { df, N: new Set(hostOf.values()).size };
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
    select: { id: true, hostname: true, username: true, organizationId: true },
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

  const { df, N } = await hostPrevalence(newCorrelations, Array.from(new Set(investigations.map((i) => i.organizationId ?? null))));
  const useRarity = N >= RARITY_MIN_HOSTS;

  function prevalenceFor(type: string, value: string, hostCount: number): Prevalence | null {
    if (!useRarity) return null;
    return { hosts: Math.max(df.get(`${type}::${value}`) ?? 0, hostCount), of: N };
  }

  // Rarity-weighted: 40% type weight, 60% rarity (an IDF over hosts on
  // record, scaled so a value on just two hosts scores 1 and one on every
  // host scores 0). Without rarity: type base plus 10 per host.
  function confidenceFor(type: string, hostCount: number, prevalence: Prevalence | null): number {
    const base = TYPE_BASE_CONFIDENCE[type] ?? 50;
    if (!prevalence) return Math.min(100, base + hostCount * 10);
    const { hosts, of } = prevalence;
    const rarity = Math.max(0, Math.min(1, Math.log(of / Math.max(hosts, 2)) / Math.log(of / 2)));
    return Math.round(0.4 * base + 60 * rarity);
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
      const prevalence        = prevalenceFor(corr.correlationType, corr.value, mergedHostCount);
      const metadata = existing.metadata && typeof existing.metadata === "object" && !Array.isArray(existing.metadata) ? existing.metadata : {};
      await prisma.correlation.update({
        where: { id: existing.id },
        data: {
          value: corr.value,
          confidence: confidenceFor(corr.correlationType, mergedHostCount, prevalence),
          metadata: { ...metadata, prevalence },
          hosts: mergedHosts,
          investigationIds: mergedInvIds,
          evidenceIds: mergedEvidenceIds,
        },
      });
    } else {
      const prevalence = prevalenceFor(corr.correlationType, corr.value, corr.hostCount);
      await prisma.correlation.create({
        data: {
          caseId: corr.caseId,
          correlationType: corr.correlationType,
          value: corr.value,
          confidence: confidenceFor(corr.correlationType, corr.hostCount, prevalence),
          metadata: { prevalence },
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
