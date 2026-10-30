export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { isSignificant } from "@/lib/correlation/explain";
import { fetchRawRows, groupRows, lookupKnownIocs, IOC_CORRELATION_TYPES } from "@/lib/correlation/group";
import type { ExtraSourceRef } from "@/lib/correlation/engine";

const GRAPH_CAP = 150;

type NodeDef = { id: string; type: string; data: Record<string, unknown> };
type EdgeDef = { id: string; source: string; target: string };

/**
 * GET /api/correlations/graph
 * Cross-case network view: case -> host -> correlation. Correlations are
 * grouped by (correlationType, value) exactly as the list view does, so a
 * value shared by several cases is one node, and hosts are one node per
 * hostname so a machine seen in several cases ties them together. Whitelisted
 * values are left out; by default only significant correlations are shown.
 * Node positions are computed client-side.
 */
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const { searchParams } = new URL(req.url);
  const type    = searchParams.get("type") ?? undefined;
  const minConf = Number(searchParams.get("minConfidence") ?? 0);
  const q       = searchParams.get("q") ?? undefined;
  const caseId  = searchParams.get("caseId") ?? undefined;
  const showAll = searchParams.get("all") === "1";

  const caseScope = orgWhere(actor);
  const caseFilter = Object.keys(caseScope).length > 0 ? { case: { ...caseScope } } : {};

  const rows = await fetchRawRows({
    ...caseFilter,
    caseId: caseId ?? { not: null },
    ...(type ? { correlationType: type } : {}),
    ...(q    ? { value: { contains: q, mode: "insensitive" as const } } : {}),
    confidence: { gte: minConf },
  });

  const orgIds = actor.organizationIds;
  const whitelist = await prisma.correlationWhitelist.findMany({
    where: orgIds ? { organizationId: { in: orgIds } } : {},
    select: { correlationType: true, value: true },
  });
  const whitelistSet = new Set(whitelist.map((w) => `${w.correlationType}::${w.value.toLowerCase()}`));

  const groupList = Array.from(groupRows(rows).values())
    .filter((g) => !whitelistSet.has(`${g.correlationType}::${g.value.toLowerCase()}`));
  const iocByValue = await lookupKnownIocs(Array.from(new Set(
    groupList.filter((g) => IOC_CORRELATION_TYPES.has(g.correlationType)).map((g) => g.value),
  )));

  const scored = groupList.map((g) => {
    const knownIoc = IOC_CORRELATION_TYPES.has(g.correlationType) ? iocByValue.get(g.value.toLowerCase()) ?? null : null;
    const significant = isSignificant({
      correlationType: g.correlationType, value: g.value,
      hosts: Array.from(g.hosts), investigationIds: Array.from(g.investigationIds), evidenceIds: [],
      distinctCaseCount: g.cases.size, confidence: g.confidence, knownIoc, prevalence: g.prevalence,
    });
    return { g, knownIoc, significant };
  });
  const totalAll = scored.length;
  const totalSignificant = scored.filter((s) => s.significant).length;

  const shown = scored
    .filter((s) => showAll || s.significant)
    .sort((a, b) =>
      Number(!!b.knownIoc) - Number(!!a.knownIoc) ||
      b.g.confidence - a.g.confidence ||
      b.g.createdAt.getTime() - a.g.createdAt.getTime())
    .slice(0, GRAPH_CAP);

  const invIds = Array.from(new Set(shown.flatMap((s) => Array.from(s.g.investigationIds))));
  const invs = invIds.length > 0
    ? await prisma.investigation.findMany({ where: { id: { in: invIds } }, select: { id: true, hostname: true, caseId: true } })
    : [];
  const hostKeyOf = (i: { id: string; hostname: string | null }) => (i.hostname ? i.hostname.toLowerCase() : `inv:${i.id}`);
  const invById = new Map(invs.map((i) => [i.id, i]));

  const nodes: NodeDef[] = [];
  const edges = new Map<string, EdgeDef>();
  const addEdge = (source: string, target: string) => {
    const id = `${source}->${target}`;
    if (!edges.has(id)) edges.set(id, { id, source, target });
  };

  const cases = new Map<string, { id: string; title: string; caseSeq: number; severity: string; status: string }>();
  for (const s of shown) for (const c of s.g.cases.values()) cases.set(c.id, c);
  for (const c of cases.values()) {
    nodes.push({
      id: `case-${c.id}`, type: "case",
      data: { label: c.title, caseId: c.id, caseSeq: c.caseSeq, severity: c.severity, status: c.status },
    });
  }

  // PCAP / RAM / log analyses are hosts too:
  // by hostname when they have one, so they merge with that machine's
  // investigations, otherwise each is its own node.
  const sourceKeyOf = (s: ExtraSourceRef) => (s.hostname ? s.hostname.toLowerCase() : `${s.kind}:${s.id}`);

  const hosts = new Map<string, { label: string; caseIds: Set<string>; kinds: Set<string> }>();
  const addHost = (key: string, label: string, kind: string, caseId: string | null) => {
    let h = hosts.get(key);
    if (!h) { h = { label, caseIds: new Set(), kinds: new Set() }; hosts.set(key, h); }
    h.kinds.add(kind);
    if (caseId && cases.has(caseId)) {
      h.caseIds.add(caseId);
      addEdge(`case-${caseId}`, `host-${key}`);
    }
  };
  for (const inv of invs) addHost(hostKeyOf(inv), inv.hostname ?? inv.id, "investigation", inv.caseId);
  for (const { g } of shown) {
    for (const src of g.sources) addHost(sourceKeyOf(src), src.hostname ?? `${src.kind.toUpperCase()} ${src.id.slice(0, 8)}`, src.kind, src.caseId);
  }
  for (const [key, h] of hosts) {
    nodes.push({ id: `host-${key}`, type: "host", data: { label: h.label, caseIds: Array.from(h.caseIds), kinds: Array.from(h.kinds) } });
  }

  for (const { g, knownIoc, significant } of shown) {
    const corrId = `corr-${g.correlationType}::${g.value}`;
    nodes.push({
      id: corrId, type: "correlation",
      data: {
        label: g.value, correlationType: g.correlationType, confidence: g.confidence,
        prevalence: g.prevalence, knownIoc, significant,
        hostCount: g.hosts.size, caseIds: Array.from(g.cases.keys()),
      },
    });
    for (const invId of g.investigationIds) {
      const inv = invById.get(invId);
      if (inv) addEdge(`host-${hostKeyOf(inv)}`, corrId);
    }
    for (const src of g.sources) addEdge(`host-${sourceKeyOf(src)}`, corrId);
  }

  return NextResponse.json({
    nodes, edges: Array.from(edges.values()),
    shown: shown.length, totalSignificant, totalAll,
    capped: (showAll ? totalAll : totalSignificant) > GRAPH_CAP, cap: GRAPH_CAP,
  });
}
