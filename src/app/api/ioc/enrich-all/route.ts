export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { deriveScopedIocSources } from "@/lib/ioc/scope";
import { getEnrichmentQueue } from "@/lib/jobs/queues";
import { matchUrlhausFeed } from "@/lib/intelligence/urlhaus-feed";

// Manual action, explicitly triggered — bounded generously, but still capped
// so one click can't accidentally queue an unbounded number of external API calls.
const MAX_LIVE_ENRICH_PER_CLICK = 500;

/**
 * POST /api/ioc/enrich-all — catch-up action, split into two independent
 * targets so an IocRecord that already has SOME provider results (e.g. from
 * the single-IOC "Enrich IOC" button) still gets checked against the free
 * local URLhaus feed, which is a different thing from "never enriched at
 * all" (the only case that queues costed/rate-limited live providers).
 * Body: { caseId?: string }.
 */
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const body = await req.json().catch(() => ({}));
  const caseId = typeof body.caseId === "string" ? body.caseId : undefined;

  const { valueFilter } = await deriveScopedIocSources(actor, caseId);
  if (valueFilter && valueFilter.in.length === 0) {
    return NextResponse.json({ feedChecked: 0, feedMatches: 0, queued: 0 });
  }
  const scopeWhere = valueFilter ? { value: valueFilter } : {};

  // Tier 1 — free local feed match: every url-type IocRecord that hasn't
  // specifically been checked against the URLhaus feed cache yet, regardless
  // of whether some other provider already ran against it.
  const feedCandidates = await prisma.iocRecord.findMany({
    where: {
      ...scopeWhere,
      type: "url",
      enrichments: { none: { provider: "urlhaus_feed" } },
    },
    select: { id: true, value: true, type: true },
  });
  const feedMatches = await matchUrlhausFeed(feedCandidates);

  // Tier 2 — live providers: only IocRecords never enriched by anything at
  // all, since this spends real quota/rate limit.
  const neverEnriched = await prisma.iocRecord.findMany({
    where: { ...scopeWhere, enrichedAt: null },
    select: { id: true, value: true, type: true },
    take: MAX_LIVE_ENRICH_PER_CLICK,
  });
  const eligible = neverEnriched.filter((r): r is { id: string; value: string; type: "ip" | "hash" | "url" | "domain" | "email" } =>
    ["ip", "hash", "url", "domain", "email"].includes(r.type)
  );

  const queue = getEnrichmentQueue();
  let queued = 0;
  for (const rec of eligible) {
    try {
      const job = await queue.add("enrich", { iocRecordId: rec.id, value: rec.value, type: rec.type, organizationId: actor.organizationIds[0] });
      await prisma.iocRecord.update({ where: { id: rec.id }, data: { enrichJobId: job.id ?? null } });
      queued++;
    } catch (err) {
      console.warn("[enrich-all] Failed to queue enrichment for", rec.value, err instanceof Error ? err.message : err);
    }
  }

  return NextResponse.json({
    feedChecked: feedCandidates.length,
    feedMatches,
    queued,
    truncated: eligible.length >= MAX_LIVE_ENRICH_PER_CLICK,
  });
}
