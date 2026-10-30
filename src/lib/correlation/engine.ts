import type { Prisma } from "@prisma/client";
import { prisma } from "@/lib/db/prisma";
import { isSignificant } from "@/lib/correlation/explain";
import { lookupKnownIocs, IOC_CORRELATION_TYPES, type KnownIoc } from "@/lib/correlation/group";

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
 * correlateCases() can also run over several cases at once, so a value on a
 * host in one case and a host in another is found too. Each case involved
 * in such a link gets (or merges into) its own record carrying the whole
 * link, with the other cases listed in metadata.linkedCaseIds. Closed and
 * archived cases are read but never written. Callers may add evidence
 * sources beyond investigations through a CorrelationSourceProvider.
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
export function hostKey(hostname: string | null, fallback: string): string {
  return hostname ? hostname.trim().toLowerCase().split(".")[0] : fallback;
}

// ── Sources ─────────────────────────────────────────────────────────────────

/** Where an observed value came from. Investigations are built in; other kinds come from a provider. */
export type CorrelationSource = {
  /** Unique across kinds: an investigation's id, or e.g. "pcap:<uploadId>". */
  id: string;
  kind: string;
  caseId: string | null;
  /** Display name; also the host identity (see hostKey). Null makes the source its own host. */
  hostname: string | null;
};

/** A non-investigation source as stored on a correlation, in metadata.sources. */
export type ExtraSourceRef = { kind: string; id: string; hostname: string | null; caseId: string | null };

export type Observation = { sourceId: string; type: string; raw: string; evidenceId?: string };

export type PrevalenceCandidate = { correlationType: string; value: string; rawValues: string[] };

/**
 * Extra evidence sources (e.g. PCAP, RAM and log analyses) for correlateCases().
 * prevalence() reports, for each `type::canonical value` candidate, the host
 * keys carrying it among this provider's sources in the given organisations,
 * and every host key it has on record there — both merged with the
 * investigation counts so rarity covers all sources.
 */
export interface CorrelationSourceProvider {
  collect(caseIds: string[]): Promise<{ sources: CorrelationSource[]; observations: Observation[] }>;
  prevalence(candidates: PrevalenceCandidate[], orgIds: (string | null)[]): Promise<{ hostsByKey: Map<string, Set<string>>; hosts: Set<string> }>;
  /** Stored form of one of this provider's sources. */
  ref(source: CorrelationSource): ExtraSourceRef;
}

const EVIDENCE_COLUMN: Record<string, "hash" | "ip" | "domain" | "url" | "processName" | "username"> = {
  shared_hash: "hash", shared_ip: "ip", shared_domain: "domain", shared_url: "url",
  shared_process: "processName", shared_account: "username",
};
const FINDING_COLUMN: Record<string, "findingType" | "category"> = {
  shared_finding_type: "findingType", shared_category: "category",
};

/** Prisma where-clause for rows in any of the given organisations (null = no organisation). */
export function orgScopeWhere(orgIds: (string | null)[]) {
  const realOrgIds = orgIds.filter((o): o is string => !!o);
  return {
    OR: [
      ...(realOrgIds.length > 0 ? [{ organizationId: { in: realOrgIds } }] : []),
      ...(orgIds.includes(null) ? [{ organizationId: null }] : []),
    ],
  };
}

/**
 * Every spelling that canonicalises to a candidate: the case's own raw
 * spellings, the canonical form, and its trailing-dot variant; meant to be
 * matched case-insensitively so other hosts' spellings are counted too.
 */
export function candidateVariants(candidates: PrevalenceCandidate[]): string[] {
  return Array.from(new Set(candidates.flatMap((c) => [c.value, `${c.value}.`, ...c.rawValues])));
}

/**
 * Host prevalence for each candidate (type::canonical value), counted over
 * every investigation in the same organisation(s) as the case — never across
 * tenants — plus the provider's own sources. Uses GROUP BY (investigation,
 * value) so common values cost one row per host rather than one per evidence
 * row.
 */
async function hostPrevalence(
  candidates: PrevalenceCandidate[],
  orgIds: (string | null)[],
  provider?: CorrelationSourceProvider,
): Promise<{ df: Map<string, number>; N: number }> {
  const orgScope = orgScopeWhere(orgIds);
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
    const variants = candidateVariants(candidates.filter((c) => c.correlationType === type));
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

  const allHosts = new Set(hostOf.values());
  if (provider) {
    const extra = await provider.prevalence(candidates, orgIds);
    for (const h of extra.hosts) allHosts.add(h);
    for (const [key, hosts] of extra.hostsByKey) {
      let s = seen.get(key);
      if (!s) seen.set(key, (s = new Set()));
      for (const h of hosts) s.add(h);
    }
  }

  const df = new Map(Array.from(seen.entries()).map(([k, s]) => [k, s.size]));
  return { df, N: allHosts.size };
}

// ── Run ─────────────────────────────────────────────────────────────────────

type Group = {
  invIds: Set<string>; hosts: Set<string>; hostKeys: Set<string>; evidenceIds: Set<string>;
  rawValues: Set<string>; caseIds: Set<string>; extraSourceIds: Set<string>;
};

/** A link that became significant in this run (new, or below the bar before). */
export type NewlySignificantCorrelation = {
  correlationType: string;
  value: string;
  confidence: number;
  hosts: string[];
  caseIds: string[];
  prevalence: Prevalence | null;
  knownIoc: KnownIoc | null;
};

export interface CorrelationRunResult {
  found: number;
  investigations: number;
  /** Non-investigation sources included (provider runs only). */
  sources?: number;
  newlySignificant?: NewlySignificantCorrelation[];
}

type Investigation = { id: string; hostname: string | null; username: string | null; organizationId: string | null; caseId: string | null };
const INVESTIGATION_SELECT = { id: true, hostname: true, username: true, organizationId: true, caseId: true } as const;

/** Correlate the given investigations into one case (every record is written with `caseId`). */
export async function runCorrelation(investigationIds: string[], caseId: string): Promise<CorrelationRunResult> {
  const investigations = await prisma.investigation.findMany({
    where: { id: { in: investigationIds } },
    select: INVESTIGATION_SELECT,
  });
  if (investigations.length < 2) {
    throw new Error("Need at least 2 investigations to correlate");
  }
  return correlate(investigations, { sources: [], observations: [] }, undefined, () => [caseId]);
}

/**
 * Correlate everything in the given cases together — their investigations
 * and, with a provider, its sources. Links are written to every open case
 * they involve.
 */
export async function correlateCases(caseIds: string[], provider?: CorrelationSourceProvider): Promise<CorrelationRunResult> {
  const [cases, investigations, extra] = await Promise.all([
    prisma.case.findMany({ where: { id: { in: caseIds } }, select: { id: true, status: true, archivedAt: true } }),
    prisma.investigation.findMany({ where: { caseId: { in: caseIds } }, select: INVESTIGATION_SELECT }),
    provider ? provider.collect(caseIds) : Promise.resolve({ sources: [], observations: [] }),
  ]);
  const writable = new Set(cases.filter((c) => c.status !== "closed" && !c.archivedAt).map((c) => c.id));
  const hostCount = new Set([
    ...investigations.map((i) => hostKey(i.hostname, i.id)),
    ...extra.sources.map((s) => hostKey(s.hostname, s.id)),
  ]).size;
  if (hostCount < 2) {
    throw new Error("Need evidence from at least 2 hosts to correlate");
  }
  return correlate(investigations, extra, provider, (g) => Array.from(g.caseIds).filter((c) => writable.has(c)));
}

async function correlate(
  investigations: Investigation[],
  extra: { sources: CorrelationSource[]; observations: Observation[] },
  provider: CorrelationSourceProvider | undefined,
  targetCases: (g: Group) => string[],
): Promise<CorrelationRunResult> {
  const invIds = investigations.map((i) => i.id);
  const invIdSet = new Set(invIds);
  const sourceById = new Map<string, CorrelationSource>([
    ...investigations.map((i) => [i.id, { id: i.id, kind: "investigation", caseId: i.caseId, hostname: i.hostname }] as const),
    ...extra.sources.map((s) => [s.id, s] as const),
  ]);

  const groupsByType = new Map<string, Map<string, Group>>();
  function observe(type: string, raw: string, sourceId: string, evidenceId?: string) {
    const src = sourceById.get(sourceId);
    if (!src) return;
    let byValue = groupsByType.get(type);
    if (!byValue) groupsByType.set(type, (byValue = new Map()));
    const value = canonicalValue(type, raw);
    let g = byValue.get(value);
    if (!g) {
      g = { invIds: new Set(), hosts: new Set(), hostKeys: new Set(), evidenceIds: new Set(), rawValues: new Set(), caseIds: new Set(), extraSourceIds: new Set() };
      byValue.set(value, g);
    }
    if (invIdSet.has(sourceId)) g.invIds.add(sourceId);
    else g.extraSourceIds.add(sourceId);
    g.hosts.add(src.hostname ?? src.id);
    g.hostKeys.add(hostKey(src.hostname, src.id));
    g.rawValues.add(raw);
    if (src.caseId) g.caseIds.add(src.caseId);
    if (evidenceId) g.evidenceIds.add(evidenceId);
  }

  // Investigation.username is the account the collector ran under — on a
  // remote collection that is the responder's own account, present on every
  // host. It describes the collection, not the subject, so it is neither
  // correlated itself (no shared_user) nor counted as a shared_account.
  const collectionAccounts = new Set(
    investigations.map((i) => i.username?.trim().toLowerCase()).filter((u): u is string => !!u)
  );

  // ── 1. Shared finding types (same attack technique) ─────────────────────
  const findings = invIds.length > 0 ? await prisma.finding.findMany({
    where: { investigationId: { in: invIds } },
    select: { investigationId: true, findingType: true, category: true },
  }) : [];
  for (const f of findings) {
    observe("shared_finding_type", f.findingType, f.investigationId);
    observe("shared_category", f.category, f.investigationId);
  }

  // ── 2. Shared evidence IOC values ───────────────────────────────────────
  const evidence = invIds.length > 0 ? await prisma.evidence.findMany({
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
  }) : [];
  for (const e of evidence) {
    if (e.domain)      observe("shared_domain",  e.domain,      e.investigationId, e.id);
    if (e.ip)          observe("shared_ip",      e.ip,          e.investigationId, e.id);
    if (e.hash)        observe("shared_hash",    e.hash,        e.investigationId, e.id);
    if (e.url)         observe("shared_url",     e.url,         e.investigationId, e.id);
    if (e.processName) observe("shared_process", e.processName, e.investigationId, e.id);
    if (e.username && !collectionAccounts.has(e.username.trim().toLowerCase())) {
      observe("shared_account", e.username, e.investigationId, e.id);
    }
  }

  // ── 3. Provider sources (e.g. PCAP / RAM / log analyses) ────────────────
  // The responder's account shows up in a DC's logon log as well; same rule.
  for (const o of extra.observations) {
    if (o.type === "shared_account" && collectionAccounts.has(o.raw.trim().toLowerCase())) continue;
    observe(o.type, o.raw, o.sourceId, o.evidenceId);
  }

  // ── Build correlations ──────────────────────────────────────────────────
  const newCorrelations: { correlationType: string; value: string; rawValues: string[]; group: Group }[] = [];
  for (const type of Object.keys(TYPE_BASE_CONFIDENCE)) {
    for (const [value, group] of groupsByType.get(type) ?? []) {
      if (group.hostKeys.size >= 2) {
        newCorrelations.push({ correlationType: type, value, rawValues: Array.from(group.rawValues), group });
      }
    }
  }

  const orgIds = new Set<string | null>(investigations.map((i) => i.organizationId ?? null));
  const extraCaseIds = Array.from(new Set(extra.sources.map((s) => s.caseId).filter((c): c is string => !!c)));
  if (extraCaseIds.length > 0) {
    const caseOrgs = await prisma.case.findMany({ where: { id: { in: extraCaseIds } }, select: { organizationId: true } });
    for (const c of caseOrgs) orgIds.add(c.organizationId ?? null);
  }
  const { df, N } = await hostPrevalence(newCorrelations, Array.from(orgIds), provider);
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

  // Significance needs the IOC verdict; it is what decides whether a link
  // is newly worth an analyst's attention (reported back to the caller).
  const iocByValue = await lookupKnownIocs(Array.from(new Set(
    newCorrelations.filter((c) => IOC_CORRELATION_TYPES.has(c.correlationType)).map((c) => c.value),
  )));
  const newlySignificant: NewlySignificantCorrelation[] = [];

  let created = 0;
  for (const corr of newCorrelations) {
    const { group } = corr;
    const targets = targetCases(group);
    if (targets.length === 0) continue;
    const knownIoc = IOC_CORRELATION_TYPES.has(corr.correlationType) ? iocByValue.get(corr.value.toLowerCase()) ?? null : null;
    const extraRefs = provider ? Array.from(group.extraSourceIds).map((id) => provider.ref(sourceById.get(id)!)) : [];
    const linkedCaseIds = group.caseIds.size > 1 ? Array.from(group.caseIds) : [];

    let wasSignificant = false;
    let best: { confidence: number; hosts: string[]; prevalence: Prevalence | null; caseCount: number } | null = null;

    for (const caseId of targets) {
      // Earlier runs stored values as the source spelled them; match those too
      // so a re-run merges into (and canonicalises) the existing record rather
      // than creating a duplicate next to it.
      const existing = await prisma.correlation.findFirst({
        where: { caseId, correlationType: corr.correlationType, value: { in: Array.from(new Set([corr.value, ...corr.rawValues])) } },
      });
      const meta: Record<string, unknown> = existing?.metadata && typeof existing.metadata === "object" && !Array.isArray(existing.metadata)
        ? existing.metadata as Record<string, unknown> : {};
      const oldSources = Array.isArray(meta.sources) ? meta.sources as ExtraSourceRef[] : [];
      const oldLinked = Array.isArray(meta.linkedCaseIds) ? meta.linkedCaseIds as string[] : [];

      if (existing) {
        wasSignificant ||= isSignificant({
          correlationType: corr.correlationType, value: corr.value, hosts: existing.hosts,
          investigationIds: existing.investigationIds, evidenceIds: [], confidence: existing.confidence,
          distinctCaseCount: Math.max(1, oldLinked.length), knownIoc,
          prevalence: (meta.prevalence as Prevalence | null | undefined) ?? null,
        });
      }

      // One name per machine: "WS-11" and a log's "ws-11.corp.local" are one host.
      const byHostKey  = new Map<string, string>();
      for (const h of [...(existing?.hosts ?? []), ...group.hosts]) if (!byHostKey.has(hostKey(h, h))) byHostKey.set(hostKey(h, h), h);
      const hosts      = Array.from(byHostKey.values());
      const hostCount  = hosts.length;
      const prevalence = prevalenceFor(corr.correlationType, corr.value, hostCount);
      const confidence = confidenceFor(corr.correlationType, hostCount, prevalence);
      const sources    = mergeSources(oldSources, extraRefs);
      const linked     = Array.from(new Set([...oldLinked, ...linkedCaseIds]));
      const metadata   = {
        ...meta, prevalence,
        ...(sources.length > 0 ? { sources } : {}),
        ...(linked.length > 0 ? { linkedCaseIds: linked } : {}),
      } as Prisma.InputJsonObject;
      const data = {
        value: corr.value, confidence, metadata, hosts,
        investigationIds: Array.from(new Set([...(existing?.investigationIds ?? []), ...group.invIds])),
        evidenceIds: Array.from(new Set([...(existing?.evidenceIds ?? []), ...group.evidenceIds])),
      };
      if (existing) {
        await prisma.correlation.update({ where: { id: existing.id }, data });
      } else {
        await prisma.correlation.create({ data: { ...data, caseId, correlationType: corr.correlationType } });
      }
      if (!best || confidence > best.confidence) {
        best = { confidence, hosts, prevalence, caseCount: Math.max(1, linked.length) };
      }
    }

    if (best && !wasSignificant && isSignificant({
      correlationType: corr.correlationType, value: corr.value, hosts: best.hosts,
      investigationIds: Array.from(group.invIds), evidenceIds: [], confidence: best.confidence,
      distinctCaseCount: best.caseCount, knownIoc, prevalence: best.prevalence,
    })) {
      newlySignificant.push({
        correlationType: corr.correlationType, value: corr.value, confidence: best.confidence,
        hosts: best.hosts, caseIds: Array.from(group.caseIds), prevalence: best.prevalence, knownIoc,
      });
    }
    created++;
  }

  return {
    found: created,
    investigations: invIds.length,
    ...(provider ? { sources: extra.sources.length } : {}),
    newlySignificant,
  };
}

function mergeSources(a: ExtraSourceRef[], b: ExtraSourceRef[]): ExtraSourceRef[] {
  const out = new Map<string, ExtraSourceRef>();
  for (const s of [...a, ...b]) out.set(`${s.kind}:${s.id}`, s);
  return Array.from(out.values());
}
