export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { deriveScopedIocSources, sourcesForValues, labelSources } from "@/lib/ioc/scope";

// GET /api/ioc/list — paginated list of IocRecords scoped to a case,
// annotated with which module(s) surfaced each one.
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  const { searchParams } = new URL(req.url);
  const q      = searchParams.get("q") ?? undefined;
  const limit  = Math.min(Number(searchParams.get("limit") ?? 50), 200);
  const offset = Number(searchParams.get("offset") ?? 0);
  const type   = searchParams.get("type") ?? undefined;
  const caseId = searchParams.get("caseId") ?? undefined;
  if (!caseId) {
    return NextResponse.json({ error: "missing_case", message: "caseId is required." }, { status: 400 });
  }
  const minReputationParam = searchParams.get("minReputation");
  const minReputation = minReputationParam !== null ? Number(minReputationParam) : undefined;
  const maxReputationParam = searchParams.get("maxReputation");
  const maxReputation = maxReputationParam !== null ? Number(maxReputationParam) : undefined;

  const reputationFilter: { gte?: number; lte?: number } = {};
  if (minReputation !== undefined && Number.isFinite(minReputation)) reputationFilter.gte = minReputation;
  if (maxReputation !== undefined && Number.isFinite(maxReputation)) reputationFilter.lte = maxReputation;

  const { valueFilter, sources: scopedSources, needsScoping } = await deriveScopedIocSources(actor, caseId);
  if (valueFilter && valueFilter.in.length === 0) return NextResponse.json({ iocs: [] });

  const iocs = await prisma.iocRecord.findMany({
    where: {
      ...(valueFilter ? { value: valueFilter } : {}),
      ...(q ? { value: { contains: q, mode: "insensitive" } } : {}),
      ...(type ? { type } : {}),
      ...(Object.keys(reputationFilter).length > 0 ? { reputation: reputationFilter } : {}),
    },
    include: {
      enrichments: {
        select: { provider: true, status: true, enrichedAt: true },
        orderBy: { enrichedAt: "desc" },
      },
    },
    orderBy: { createdAt: "desc" },
    take: limit,
    skip: offset,
  });

  // Source labels for this page. If scoping already walked every module
  // (non-admin or case-filtered), reuse that map. Otherwise (platform admin,
  // no case filter) resolve sources for just this page's values directly —
  // cheaper than repeating the full org-wide join for an unscoped request.
  const pageSources = needsScoping ? scopedSources : await sourcesForValues(iocs.map((i) => i.value));

  const iocsWithSource = iocs.map((ioc) => ({
    ...ioc,
    sources: labelSources(pageSources.get(ioc.value), ioc.enrichments.length),
  }));

  return NextResponse.json({ iocs: iocsWithSource });
}
