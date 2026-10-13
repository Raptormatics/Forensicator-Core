/**
 * Windows Artifact Analysis worker. Processes jobs from the
 * "forensicator-winartifacts" queue — one job per WindowsArtifactFile, not
 * per collection (see src/lib/windows-artifacts/processor.ts's own header
 * comment for why). Deliberately a THIN wrapper — all status-lifecycle
 * bookkeeping lives in processWindowsArtifactFile() itself, matching
 * processRamUpload's pattern. concurrency:2 — registry hives are small and
 * fast to parse, same reasoning as PCAP's concurrency:2.
 */
import { Worker, Job } from "bullmq";
import { getRedisConnection } from "./redis";
import { prisma } from "@/lib/db/prisma";
import type { WinArtifactJobData } from "./queues";
import { processWindowsArtifactFile } from "@/lib/windows-artifacts/processor";

const WIN_ARTIFACTS_QUEUE = "forensicator-winartifacts";

async function processWinArtifactJob(job: Job<WinArtifactJobData>) {
  const file = await prisma.windowsArtifactFile.findUniqueOrThrow({ where: { id: job.data.winArtifactFileId } });
  if (!file.storagePath) throw new Error(`WindowsArtifactFile ${file.id} has no storagePath`);
  await processWindowsArtifactFile(file.id, file.storagePath);
}

export function startWinArtifactsWorker() {
  const worker = new Worker<WinArtifactJobData>(WIN_ARTIFACTS_QUEUE, processWinArtifactJob, {
    connection: getRedisConnection(),
    concurrency: 2,
  });
  worker.on("error", (err) => console.error("[winartifacts-worker]", err));
  return worker;
}
