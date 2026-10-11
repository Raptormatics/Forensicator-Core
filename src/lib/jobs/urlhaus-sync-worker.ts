/**
 * URLhaus feed sync worker. Refreshes the local bulk-feed cache (see
 * src/lib/intelligence/urlhaus-feed.ts) on a repeatable schedule, plus
 * handles on-demand syncs triggered from the Threat Intel page's "Sync Now".
 */
import { Worker, Job } from "bullmq";
import { getRedisConnection } from "./redis";
import { getUrlhausSyncQueue, type UrlhausSyncJobData } from "./queues";
import { syncUrlhausFeed } from "@/lib/intelligence/urlhaus-feed";

const URLHAUS_SYNC_QUEUE = "forensicator-urlhaus-sync";
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;

async function processUrlhausSync(_job: Job<UrlhausSyncJobData>) {
  const result = await syncUrlhausFeed();
  console.log(`[urlhaus-sync] Synced feed: ${result.added} new / ${result.total} total entries.`);
  return result;
}

export function startUrlhausSyncWorker() {
  const worker = new Worker<UrlhausSyncJobData>(URLHAUS_SYNC_QUEUE, processUrlhausSync, {
    connection: getRedisConnection(),
    concurrency: 1,
  });
  worker.on("error", (err) => console.error("[urlhaus-sync-worker]", err));
  return worker;
}

/**
 * Registers the repeatable schedule and queues one immediate run — call
 * once at worker startup. Re-adding the same repeat options on every
 * restart is a no-op (BullMQ dedupes repeatable jobs by their repeat key),
 * so this is safe to call unconditionally.
 */
export async function scheduleUrlhausSync() {
  const queue = getUrlhausSyncQueue();
  await queue.add("sync", {}, { repeat: { every: SIX_HOURS_MS }, jobId: "urlhaus-feed-schedule" });
  await queue.add("sync-now", {});
  await queue.close();
}
