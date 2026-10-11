/**
 * IOC enrichment worker.
 * Processes jobs from the "forensicator:enrichment" queue.
 */
import { Worker, Job } from "bullmq";
import { getRedisConnection } from "./redis";
import { enrichIoc } from "@/lib/intelligence/enrichment";
import type { EnrichmentJobData } from "./queues";

const ENRICHMENT_QUEUE = "forensicator-enrichment";

async function processEnrichment(job: Job<EnrichmentJobData>) {
  const { iocRecordId, value, type, organizationId } = job.data;
  console.log(`[enrichment-worker] enriching ${type}:${value}`);
  await enrichIoc(iocRecordId, value, type, organizationId);
}

export function startEnrichmentWorker() {
  const worker = new Worker<EnrichmentJobData>(ENRICHMENT_QUEUE, processEnrichment, {
    connection: getRedisConnection(),
    concurrency: 5,
  });
  worker.on("error", (err) => console.error("[enrichment-worker]", err));
  return worker;
}
