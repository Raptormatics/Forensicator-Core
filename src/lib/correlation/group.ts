/**
 * Shared (correlationType, value) grouping logic for the Correlations list
 * and on-demand explain routes — kept in one place so both derive the exact
 * same entity from the same underlying rows.
 */
import { prisma } from "@/lib/db/prisma";

// Safety cap on raw rows pulled into a grouping pass — well beyond any
// realistic single-tenant correlation volume, just a backstop.
export const MAX_GROUPING_ROWS = 10_000;

export async function fetchRawRows(where: Record<string, unknown>) {
  return prisma.correlation.findMany({
    where,
    select: {
      id: true, caseId: true, correlationType: true, value: true, confidence: true,
      hosts: true, investigationIds: true, evidenceIds: true, createdAt: true,
      case: { select: { id: true, title: true, caseSeq: true, severity: true, status: true } },
    },
    take: MAX_GROUPING_ROWS,
  });
}

export type RawRow = Awaited<ReturnType<typeof fetchRawRows>>[number];

export type CorrelationGroup = {
  correlationType: string;
  value: string;
  confidence: number;
  hosts: Set<string>;
  investigationIds: Set<string>;
  evidenceIds: Set<string>;
  cases: Map<string, { id: string; title: string; caseSeq: number; severity: string; status: string }>;
  createdAt: Date;
  rows: RawRow[];
};

export function groupRows(rows: RawRow[]): Map<string, CorrelationGroup> {
  const groups = new Map<string, CorrelationGroup>();
  for (const r of rows) {
    const key = `${r.correlationType}::${r.value}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        correlationType: r.correlationType, value: r.value, confidence: 0,
        hosts: new Set(), investigationIds: new Set(), evidenceIds: new Set(),
        cases: new Map(), createdAt: r.createdAt, rows: [],
      };
      groups.set(key, g);
    }
    g.confidence = Math.max(g.confidence, r.confidence);
    for (const h of r.hosts) g.hosts.add(h);
    for (const i of r.investigationIds) g.investigationIds.add(i);
    for (const e of r.evidenceIds) g.evidenceIds.add(e);
    if (r.case) g.cases.set(r.case.id, r.case);
    if (r.createdAt > g.createdAt) g.createdAt = r.createdAt;
    g.rows.push(r);
  }
  return groups;
}
