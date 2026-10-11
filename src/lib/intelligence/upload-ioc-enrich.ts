/**
 * Manual "Enrich" action for a single Log/PCAP/RAM upload's already-extracted
 * IOC tally (LogIoc/PcapIoc/RamIoc). Each upload's processor already runs an
 * automatic pass at upload time (see src/lib/log-analysis/processor.ts etc.)
 * that upserts an IocRecord per value and auto-enriches genuinely-new ones —
 * but a value that already existed as an IocRecord from some earlier upload
 * is never counted as "new" there, so it can sit permanently unenriched even
 * though nothing ever actually checked it. This re-runs the same upsert plus
 * a scoped version of the two-tier catch-up already used by the global
 * "Enrich All Unenriched" button (src/app/api/ioc/enrich-all/route.ts), but
 * limited to this upload's own IOC values instead of every IocRecord platform-wide.
 */
import { prisma } from "@/lib/db/prisma";
import { getEnrichmentQueue } from "@/lib/jobs/queues";
import { matchUrlhausFeed } from "./urlhaus-feed";

const MAX_LIVE_ENRICH_PER_UPLOAD = 100;

export type EnrichableIoc = { value: string; type: "ip" | "hash" | "url" | "domain" | "email" };

export type UploadEnrichResult = {
  uniqueIocs: number;
  newRecords: number;
  feedMatches: number;
  queued: number;
  truncated: boolean;
};

export async function enrichUploadIocs(
  values: EnrichableIoc[],
  organizationId?: string
): Promise<UploadEnrichResult> {
  if (values.length === 0) return { uniqueIocs: 0, newRecords: 0, feedMatches: 0, queued: 0, truncated: false };

  // A tally table can list the same value under more than one raw type in
  // edge cases; IocRecord is keyed by value alone, so dedupe here.
  const byValue = new Map<string, EnrichableIoc["type"]>();
  for (const v of values) if (!byValue.has(v.value)) byValue.set(v.value, v.type);

  const now = new Date();
  let newRecords = 0;
  for (const [value, type] of byValue) {
    try {
      const rec = await prisma.iocRecord.upsert({
        where: { value },
        create: { value, type, firstSeen: now, lastSeen: now },
        update: { lastSeen: now },
      });
      if (rec.firstSeen?.getTime() === now.getTime()) newRecords++;
    } catch (err) {
      console.warn("[upload-ioc-enrich] IocRecord upsert skipped:", value.slice(0, 80), err instanceof Error ? err.message : err);
    }
  }

  const allValues = [...byValue.keys()];

  // Tier 1 — free local feed match: url-type values not yet checked against
  // the URLhaus feed cache, regardless of any other provider's status.
  const feedCandidates = await prisma.iocRecord.findMany({
    where: { value: { in: allValues }, type: "url", enrichments: { none: { provider: "urlhaus_feed" } } },
    select: { id: true, value: true, type: true },
  });
  const feedMatches = await matchUrlhausFeed(feedCandidates).catch((err) => {
    console.warn("[upload-ioc-enrich] URLhaus feed match failed:", err instanceof Error ? err.message : err);
    return 0;
  });

  // Tier 2 — live providers: values never enriched by anything at all.
  const neverEnriched = await prisma.iocRecord.findMany({
    where: { value: { in: allValues }, enrichedAt: null },
    select: { id: true, value: true, type: true },
    take: MAX_LIVE_ENRICH_PER_UPLOAD,
  });
  const eligible = neverEnriched.filter((r): r is { id: string; value: string; type: EnrichableIoc["type"] } =>
    (["ip", "hash", "url", "domain", "email"] as string[]).includes(r.type)
  );

  const queue = getEnrichmentQueue();
  let queued = 0;
  for (const rec of eligible) {
    try {
      const job = await queue.add("enrich", { iocRecordId: rec.id, value: rec.value, type: rec.type, organizationId });
      await prisma.iocRecord.update({ where: { id: rec.id }, data: { enrichJobId: job.id ?? null } });
      queued++;
    } catch (err) {
      console.warn("[upload-ioc-enrich] Failed to queue enrichment for", rec.value, err instanceof Error ? err.message : err);
    }
  }

  return {
    uniqueIocs: allValues.length,
    newRecords,
    feedMatches,
    queued,
    truncated: neverEnriched.length >= MAX_LIVE_ENRICH_PER_UPLOAD,
  };
}
