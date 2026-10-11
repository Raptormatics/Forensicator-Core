/**
 * Called once per upload (investigation/log/pcap/ram), after that upload's
 * IocRecord rows have all been upserted. Two tiers:
 *   1. Free local URLhaus feed match — no rate limit, runs against every
 *      extracted URL, always.
 *   2. Live provider enrichment (VirusTotal/AbuseIPDB/URLhaus API/etc.) —
 *      queued only for genuinely NEW records (repeat uploads of already-known
 *      values don't re-spend quota), capped per upload to protect rate limits.
 */
import { prisma } from "@/lib/db/prisma";
import { getEnrichmentQueue } from "@/lib/jobs/queues";
import { matchUrlhausFeed } from "./urlhaus-feed";

const MAX_AUTO_ENRICH_PER_UPLOAD = 100;

export type NewIocRecord = { id: string; value: string; type: "ip" | "hash" | "url" | "domain" | "email" };

export async function autoEnrichNewIocs(
  newRecords: NewIocRecord[],
  organizationId?: string
): Promise<{ feedMatches: number; queued: number }> {
  if (newRecords.length === 0) return { feedMatches: 0, queued: 0 };

  const feedMatches = await matchUrlhausFeed(newRecords).catch((err) => {
    console.warn("[auto-enrich] URLhaus feed match failed:", err instanceof Error ? err.message : err);
    return 0;
  });

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
