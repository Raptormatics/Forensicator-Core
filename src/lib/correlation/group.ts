/**
 * Shared (correlationType, value) grouping logic for the Correlations list
 * and on-demand explain routes — kept in one place so both derive the exact
 * same entity from the same underlying rows.
 */
import { prisma } from "@/lib/db/prisma";
import { hostKey, type Prevalence, type ExtraSourceRef } from "@/lib/correlation/engine";

// Safety cap on raw rows pulled into a grouping pass — well beyond any
// realistic single-tenant correlation volume, just a backstop.
export const MAX_GROUPING_ROWS = 10_000;

export async function fetchRawRows(where: Record<string, unknown>) {
  return prisma.correlation.findMany({
    where,
    select: {
      id: true, caseId: true, correlationType: true, value: true, confidence: true,
      hosts: true, investigationIds: true, evidenceIds: true, metadata: true, createdAt: true, updatedAt: true,
      case: { select: { id: true, title: true, caseSeq: true, severity: true, status: true } },
    },
    take: MAX_GROUPING_ROWS,
  });
}

export type RawRow = Awaited<ReturnType<typeof fetchRawRows>>[number];

/** correlationType values whose `value` is itself a raw threat-intel-enrichable indicator. */
export const IOC_CORRELATION_TYPES = new Set(["shared_ip", "shared_domain", "shared_hash", "shared_url"]);

export type KnownIoc = { reputation: number | null; threatType: string | null; malwareFamily: string | null };

/**
 * Threat-intel records for correlation values, keyed by lower-cased value.
 * Correlation values are stored canonical (lower-case hashes/domains), while
 * IocRecord keeps each indicator as its source spelled it — feeds use lower
 * case, Windows' Get-FileHash upper case — so both spellings are looked up.
 * Only records carrying an actual verdict are returned.
 */
export async function lookupKnownIocs(values: string[]): Promise<Map<string, KnownIoc>> {
  if (values.length === 0) return new Map();
  const variants = Array.from(new Set(values.flatMap((v) => [v, v.toLowerCase(), v.toUpperCase()])));
  const records = await prisma.iocRecord.findMany({
    where: { value: { in: variants } },
    select: { value: true, reputation: true, threatType: true, malwareFamily: true },
  });
  const out = new Map<string, KnownIoc>();
  for (const r of records) {
    if (r.reputation === null && r.threatType === null) continue;
    out.set(r.value.toLowerCase(), { reputation: r.reputation, threatType: r.threatType, malwareFamily: r.malwareFamily });
  }
  return out;
}

export type CorrelationGroup = {
  correlationType: string;
  value: string;
  confidence: number;
  hosts: Set<string>;
  investigationIds: Set<string>;
  evidenceIds: Set<string>;
  cases: Map<string, { id: string; title: string; caseSeq: number; severity: string; status: string }>;
  createdAt: Date;
  /** From the most recently run row; null when it was scored without rarity. */
  prevalence: Prevalence | null;
  /** Non-investigation sources (e.g. PCAP / RAM / log analyses) involved, from every row. */
  sources: ExtraSourceRef[];
  rows: RawRow[];
};

function prevalenceOf(r: RawRow): Prevalence | null {
  const m = r.metadata as { prevalence?: Prevalence | null } | null;
  return m && typeof m === "object" && m.prevalence ? m.prevalence : null;
}

function sourcesOf(r: RawRow): ExtraSourceRef[] {
  const m = r.metadata as { sources?: unknown } | null;
  return m && typeof m === "object" && Array.isArray(m.sources) ? m.sources as ExtraSourceRef[] : [];
}

export function groupRows(rows: RawRow[]): Map<string, CorrelationGroup> {
  const groups = new Map<string, CorrelationGroup>();
  for (const r of rows) {
    const key = `${r.correlationType}::${r.value}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        correlationType: r.correlationType, value: r.value, confidence: 0,
        hosts: new Set(), investigationIds: new Set(), evidenceIds: new Set(),
        cases: new Map(), createdAt: r.createdAt, prevalence: null, sources: [], rows: [],
      };
      groups.set(key, g);
    }
    g.confidence = Math.max(g.confidence, r.confidence);
    // Rows written before the engine kept one name per machine can still
    // list "WS-11" and "ws-11.corp.local" separately.
    for (const h of r.hosts) {
      const k = hostKey(h, h);
      if (!Array.from(g.hosts).some((x) => hostKey(x, x) === k)) g.hosts.add(h);
    }
    for (const i of r.investigationIds) g.investigationIds.add(i);
    for (const e of r.evidenceIds) g.evidenceIds.add(e);
    if (r.case) g.cases.set(r.case.id, r.case);
    if (r.createdAt > g.createdAt) g.createdAt = r.createdAt;
    if (g.rows.every((o) => r.updatedAt >= o.updatedAt)) g.prevalence = prevalenceOf(r);
    for (const src of sourcesOf(r)) {
      if (!g.sources.some((o) => o.kind === src.kind && o.id === src.id)) g.sources.push(src);
    }
    g.rows.push(r);
  }
  return groups;
}
