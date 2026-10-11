/**
 * RAM Analysis worker. Processes jobs from the "forensicator-ram" queue.
 *
 * Deliberately a THIN wrapper — all status-lifecycle bookkeeping
 * (processing -> ready/failed) lives in processRamUpload() itself
 * (src/lib/ram-analysis/processor.ts), matching processPcapUpload's
 * pattern. concurrency:1 (not PCAP's 2) — Volatility3 plugins are
 * memory-hungry themselves, running two large-image analyses concurrently
 * risks starving the host.
 */
import { Worker, Job } from "bullmq";
import { getRedisConnection } from "./redis";
import { prisma } from "@/lib/db/prisma";
import type { RamJobData } from "./queues";
import { processRamUpload } from "@/lib/ram-analysis/processor";

const RAM_QUEUE = "forensicator-ram";

async function processRamJob(job: Job<RamJobData>) {
  const upload = await prisma.ramUpload.findUniqueOrThrow({ where: { id: job.data.ramUploadId } });
  if (!upload.storagePath) throw new Error(`RamUpload ${upload.id} has no storagePath`);
  await processRamUpload(upload.id, upload.storagePath);
}

export function startRamWorker() {
  const worker = new Worker<RamJobData>(RAM_QUEUE, processRamJob, {
    connection: getRedisConnection(),
    concurrency: 1,
  });
  worker.on("error", (err) => console.error("[ram-worker]", err));
  return worker;
}
