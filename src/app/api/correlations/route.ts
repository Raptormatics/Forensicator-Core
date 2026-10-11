export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import type { IocLookupInfo } from "@/lib/rule-engine/ioc-lookup";
import {
  buildDeterministicFacts, renderFactsNarrative, isSignificant,
  type GroupedCorrelationInput,
} from "@/lib/correlation/explain";
import { fetchRawRows, groupRows } from "@/lib/correlation/group";

/** correlationType values whose `value` is itself a raw threat-intel-enrichable indicator. */
const IOC_CORRELATION_TYPES = new Set(["shared_ip", "shared_domain", "shared_hash", "shared_url"]);

const SORTABLE = new Set(["confidence", "createdAt", "investigationCount"]);

// GET /api/correlations — list correlations scoped to the actor's organization,
// grouped by (correlationType, value) so the same entity (e.g. a hostname
// showing up in several cases) renders as one card instead of N duplicates.
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const { searchParams } = new URL(req.url);
  const type    = searchParams.get("type") ?? undefined;
  const minConf = Number(searchParams.get("minConfidence") ?? 0);
  const caseId  = searchParams.get("caseId") ?? undefined;
  const q       = searchParams.get("q") ?? undefined;
  const host    = searchParams.get("host") ?? undefined;
  const hideWhitelisted = searchParams.get("hideWhitelisted") === "1";
  const sortByParam = searchParams.get("sortBy") ?? "confidence";
  const sortBy  = SORTABLE.has(sortByParam) ? sortByParam : "confidence";
  const page    = Math.max(1, Number(searchParams.get("page") ?? 1));
  const limit   = Math.min(100, Math.max(1, Number(searchParams.get("limit") ?? 25)));

  // Scope: platform_admin sees all; others restricted to their org's cases
  const caseScope = orgWhere(actor);
  const caseFilter = Object.keys(caseScope).length > 0 ? { case: { ...caseScope } } : {};

  const baseWhere = {
    ...caseFilter,
    ...(caseId ? { caseId } : {}),
    ...(q      ? { value: { contains: q, mode: "insensitive" as const } } : {}),
    ...(host   ? { hosts: { has: host } } : {}),
    confidence: { gte: minConf },
  };

  const [allRows, typeCountRows] = await Promise.all([
    fetchRawRows({ ...baseWhere, ...(type ? { correlationType: type } : {}) }),
    // Pill counts ignore the `type` filter itself so switching pills stays coherent.
    fetchRawRows(baseWhere),
  ]);

  const groups = groupRows(allRows);
  const typeCountGroups = groupRows(typeCountRows);
  const countsByType = new Map<string, number>();
  for (const g of typeCountGroups.values()) countsByType.set(g.correlationType, (countsByType.get(g.correlationType) ?? 0) + 1);

  // Whitelist lookup — org-scoped (platform_admin sees all orgs' entries).
  const orgIds = actor.role !== "platform_admin" ? actor.organizationIds : undefined;
  const whitelist = await prisma.correlationWhitelist.findMany({
    where: orgIds ? { organizationId: { in: orgIds } } : {},
    select: { correlationType: true, value: true, note: true },
  });
  const whitelistSet = new Set(whitelist.map((w) => `${w.correlationType}::${w.value}`));

  let groupList = Array.from(groups.values());
  if (hideWhitelisted) groupList = groupList.filter((g) => !whitelistSet.has(`${g.correlationType}::${g.value}`));

  // IOC enrichment for known-indicator-type groups
  const iocValues = Array.from(new Set(groupList.filter((g) => IOC_CORRELATION_TYPES.has(g.correlationType)).map((g) => g.value)));
  const iocRecords = iocValues.length > 0
    ? await prisma.iocRecord.findMany({ where: { value: { in: iocValues } }, select: { value: true, reputation: true, threatType: true, malwareFamily: true } })
    : [];
  const iocByValue = new Map(iocRecords.map((r) => [r.value, r]));
  function knownIocFor(value: string, correlationType: string): IocLookupInfo | null {
    if (!IOC_CORRELATION_TYPES.has(correlationType)) return null;
    const rec = iocByValue.get(value);
    if (!rec || (rec.reputation === null && rec.threatType === null)) return null;
    return { reputation: rec.reputation, threatType: rec.threatType, malwareFamily: rec.malwareFamily };
  }

  // Sort grouped entities
  groupList.sort((a, b) => {
    if (sortBy === "createdAt") return b.createdAt.getTime() - a.createdAt.getTime();
    if (sortBy === "investigationCount") return b.investigationIds.size - a.investigationIds.size;
    return b.confidence - a.confidence || b.createdAt.getTime() - a.createdAt.getTime();
  });

  const total = groupList.length;
  const pageGroups = groupList.slice((page - 1) * limit, (page - 1) * limit + limit);

  // Human-readable investigation info for the page's groups only.
  const pageInvIds = Array.from(new Set(pageGroups.flatMap((g) => Array.from(g.investigationIds))));
  const investigations = pageInvIds.length > 0
    ? await prisma.investigation.findMany({ where: { id: { in: pageInvIds } }, select: { id: true, title: true, hostname: true, status: true } })
    : [];
  const invById = new Map(investigations.map((i) => [i.id, i]));

  const correlations = await Promise.all(pageGroups.map(async (g) => {
    const cases = Array.from(g.cases.values());
    const hostCount = g.hosts.size;
    const label = hostCount > 1 ? "Multi-Host Pivot" : cases.length > 1 ? "Cross-Case Persistence" : null;
    const knownIoc = knownIocFor(g.value, g.correlationType);

    const groupInput: GroupedCorrelationInput = {
      correlationType: g.correlationType, value: g.value,
      hosts: Array.from(g.hosts), investigationIds: Array.from(g.investigationIds), evidenceIds: Array.from(g.evidenceIds),
      distinctCaseCount: cases.length, confidence: g.confidence, knownIoc,
    };
    const significant = isSignificant(groupInput);
    let whyThisMatters: string | null = null;
    if (significant) {
      const facts = await buildDeterministicFacts(groupInput);
      whyThisMatters = renderFactsNarrative(facts);
    }

    return {
      id: `${g.correlationType}::${g.value}`,
      correlationType: g.correlationType,
      value: g.value,
      confidence: g.confidence,
      hosts: Array.from(g.hosts),
      investigationIds: Array.from(g.investigationIds),
      investigations: Array.from(g.investigationIds).map((id) => invById.get(id)).filter((i): i is NonNullable<typeof i> => !!i),
      cases,
      createdAt: g.createdAt.toISOString(),
      knownIoc,
      label,
      isWhitelisted: whitelistSet.has(`${g.correlationType}::${g.value}`),
      significant,
      whyThisMatters,
      rowCount: g.rows.length,
    };
  }));

  // Stats over the entire filtered (grouped) set, not just the page.
  // `total` is the count of (correlationType, value) groups — i.e. distinct
  // relationship points where investigations share something, which can
  // exceed the count of distinct raw values below when the same value
  // qualifies under more than one correlationType.
  let confidenceSum = 0;
  let knownIocMatches = 0;
  for (const g of groupList) {
    confidenceSum += g.confidence;
    if (knownIocFor(g.value, g.correlationType)) knownIocMatches++;
  }
  const distinctEntities = new Set(groupList.map((g) => g.value)).size;

  const stats = {
    total,
    avgConfidence: total > 0 ? Math.round(confidenceSum / total) : 0,
    distinctEntities,
    knownIocMatches,
    byType: Array.from(countsByType.entries()).map(([type, count]) => ({ type, count })),
  };

  return NextResponse.json({ correlations, total, page, limit, stats });
}
