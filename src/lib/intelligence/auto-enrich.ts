/**
 * Called once per upload (investigation/log/pcap/ram), after that upload's
 * IocRecord rows have all been upserted. Two tiers:
 *   1. Free local feed matches (URLhaus for URLs, MalwareBazaar for hashes)
 *      — no rate limit, runs against every extracted value, always.
 *   2. Live provider enrichment (VirusTotal/AbuseIPDB/URLhaus API/etc.) —
 *      queued only for genuinely NEW records (repeat uploads of already-known
 *      values don't re-spend quota), capped per upload to protect rate limits.
 */
import { prisma } from "@/lib/db/prisma";
import { getEnrichmentQueue } from "@/lib/jobs/queues";
import { matchUrlhausFeed } from "./urlhaus-feed";
import { matchMalwareBazaarFeed } from "./malwarebazaar-feed";

const MAX_AUTO_ENRICH_PER_UPLOAD = 100;

export type NewIocRecord = { id: string; value: string; type: "ip" | "hash" | "url" | "domain" | "email" };

export async function autoEnrichNewIocs(
  newRecords: NewIocRecord[],
  organizationId?: string
): Promise<{ feedMatches: number; queued: number }> {
  if (newRecords.length === 0) return { feedMatches: 0, queued: 0 };

  // Disjoint by type (url vs hash) — safe to sum, no double-counting.
  const [urlFeedMatches, hashFeedMatches] = await Promise.all([
    matchUrlhausFeed(newRecords).catch((err) => {
      console.warn("[auto-enrich] URLhaus feed match failed:", err instanceof Error ? err.message : err);
      return 0;
    }),
    matchMalwareBazaarFeed(newRecords).catch((err) => {
      console.warn("[auto-enrich] MalwareBazaar feed match failed:", err instanceof Error ? err.message : err);
      return 0;
    }),
  ]);
  const feedMatches = urlFeedMatches + hashFeedMatches;

  const toQueue = newRecords.slice(0, MAX_AUTO_ENRICH_PER_UPLOAD);
  const queue = getEnrichmentQueue();
  let queued = 0;
  for (const rec of toQueue) {
    try {
      const job = await queue.add("enrich", { iocRecordId: rec.id, value: rec.value, type: rec.type, organizationId });
      await prisma.iocRecord.update({ where: { id: rec.id }, data: { enrichJobId: job.id ?? null } });
      queued++;
    } catch (err) {
      console.warn("[auto-enrich] Failed to queue enrichment for", rec.value, err instanceof Error ? err.message : err);
    }
  }

  return { feedMatches, queued };
}
