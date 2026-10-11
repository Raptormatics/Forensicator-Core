/**
 * PCAP Analysis worker. Processes jobs from the "forensicator-pcap" queue.
 *
 * Deliberately a THIN wrapper — all status-lifecycle bookkeeping
 * (processing -> ready/failed) lives in processPcapUpload() itself
 * (src/lib/pcap-analysis/processor.ts), matching processLogUpload's real
 * pattern. There is no "processor sets ready, worker sets failed" split
 * anywhere else in this codebase to mirror, so this worker doesn't
 * duplicate status-setting logic — it just calls the processor and lets
 * BullMQ's own retry mechanism react to the rethrown error.
 */
import { Worker, Job } from "bullmq";
import { getRedisConnection } from "./redis";
import { prisma } from "@/lib/db/prisma";
import type { PcapJobData } from "./queues";
import { processPcapUpload } from "@/lib/pcap-analysis/processor";

const PCAP_QUEUE = "forensicator-pcap";

async function processPcapJob(job: Job<PcapJobData>) {
  const upload = await prisma.pcapUpload.findUniqueOrThrow({ where: { id: job.data.pcapUploadId } });
  if (!upload.storagePath) throw new Error(`PcapUpload ${upload.id} has no storagePath`);
  await processPcapUpload(upload.id, upload.storagePath);
}

export function startPcapWorker() {
  const worker = new Worker<PcapJobData>(PCAP_QUEUE, processPcapJob, {
    connection: getRedisConnection(),
    concurrency: 2,
  });
  worker.on("error", (err) => console.error("[pcap-worker]", err));
  return worker;
}
