export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

const GRAPH_CAP = 150;

type NodeDef = { id: string; type: string; data: Record<string, unknown>; position: { x: number; y: number } };
type EdgeDef = { id: string; source: string; target: string; label?: string; style?: Record<string, unknown> };

/**
 * GET /api/correlations/graph
 * Cross-case network view: case nodes -> host nodes -> correlation nodes,
 * generalizing /api/cases/[id]/graph across every case the actor can see.
 * Capped at the top GRAPH_CAP correlations by confidence to stay legible.
 */
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const { searchParams } = new URL(req.url);
  const type    = searchParams.get("type") ?? undefined;
  const minConf = Number(searchParams.get("minConfidence") ?? 0);
  const q       = searchParams.get("q") ?? undefined;

  const caseScope = orgWhere(actor);
  const caseFilter = Object.keys(caseScope).length > 0 ? { case: { ...caseScope } } : {};

  const correlations = await prisma.correlation.findMany({
    where: {
      ...caseFilter,
      caseId: { not: null },
      ...(type ? { correlationType: type } : {}),
      ...(q    ? { value: { contains: q, mode: "insensitive" as const } } : {}),
      confidence: { gte: minConf },
    },
    orderBy: [{ confidence: "desc" }, { createdAt: "desc" }],
    take: GRAPH_CAP,
  });

  const caseIds = Array.from(new Set(correlations.map((c) => c.caseId!).filter(Boolean)));
  const invIds  = Array.from(new Set(correlations.flatMap((c) => c.investigationIds)));

  const [cases, invs] = await Promise.all([
    prisma.case.findMany({ where: { id: { in: caseIds } }, select: { id: true, title: true, status: true, severity: true } }),
    prisma.investigation.findMany({ where: { id: { in: invIds } }, select: { id: true, hostname: true, caseId: true } }),
  ]);

  const invById = new Map(invs.map((i) => [i.id, i]));
  // Each investigation belongs to at most one case, so the case<->investigation
  // "links" are just the investigations themselves, scoped to a known case.
  const caseInvLinks = invs
    .filter((i) => i.caseId && caseIds.includes(i.caseId))
    .map((i) => ({ caseId: i.caseId as string, investigationId: i.id }));

  const nodes: NodeDef[] = [];
  const edges: EdgeDef[] = [];

  // Case cluster centers on an outer ring
  const outerRadius = Math.max(500, cases.length * 180);
  const caseCenters = new Map<string, { x: number; y: number }>();
  cases.forEach((c, i) => {
    const angle = (2 * Math.PI * i) / Math.max(1, cases.length);
    const center = { x: Math.cos(angle) * outerRadius, y: Math.sin(angle) * outerRadius };
    caseCenters.set(c.id, center);
    nodes.push({
      id: `case-${c.id}`,
      type: "case",
      data: { label: c.title, status: c.status, severity: c.severity },
      position: center,
    });
  });

  // Host nodes, clustered near the (first) case they belong to; case->host dashed edges for every pairing
  const hostPlaced = new Set<string>();
  const invHostCount = new Map<string, number>();
  for (const link of caseInvLinks) {
    const center = caseCenters.get(link.caseId);
    const inv = invById.get(link.investigationId);
    if (!center || !inv) continue;

    if (!hostPlaced.has(inv.id)) {
      const idx = invHostCount.get(link.caseId) ?? 0;
      invHostCount.set(link.caseId, idx + 1);
      const hostsInCase = caseInvLinks.filter((l) => l.caseId === link.caseId).length;
      const angle = (2 * Math.PI * idx) / Math.max(1, hostsInCase);
      nodes.push({
        id: `host-${inv.id}`,
        type: "host",
        data: { label: inv.hostname ?? inv.id },
        position: { x: center.x + Math.cos(angle) * 160, y: center.y + Math.sin(angle) * 160 },
      });
      hostPlaced.add(inv.id);
    }

    edges.push({
      id: `e-case-${link.caseId}-${link.investigationId}`,
      source: `case-${link.caseId}`,
      target: `host-${link.investigationId}`,
      style: { stroke: "#475569", strokeDasharray: "4 4" },
    });
  }

  // Correlation nodes spread in a band below, connected to every involved host
  correlations.forEach((corr, i) => {
    const corrId = `corr-${corr.id}`;
    nodes.push({
      id: corrId,
      type: "correlation",
      data: { label: corr.value, correlationType: corr.correlationType, confidence: corr.confidence },
      position: { x: -GRAPH_CAP * 4 + i * 60, y: outerRadius + 400 },
    });
    for (const invId of corr.investigationIds) {
      if (!hostPlaced.has(invId)) continue;
      edges.push({
        id: `e-corr-${corr.id}-${invId}`,
        source: corrId,
        target: `host-${invId}`,
        label: corr.correlationType,
        style: { stroke: "#6366f1" },
      });
    }
  });

  return NextResponse.json({ nodes, edges, capped: correlations.length >= GRAPH_CAP, cap: GRAPH_CAP });
}
