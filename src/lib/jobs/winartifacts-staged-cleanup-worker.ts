/**
 * Sweeps abandoned chunked Windows Artifact file uploads
 * (src/prisma/schema's WindowsArtifactStagedFile) — a tab closed mid-upload,
 * a crashed browser, or a file that finished staging but whose final
 * /api/windows-artifacts/uploads POST never arrived. Runs on a repeatable
 * schedule; also a lazy check in the chunk/complete routes rejects requests
 * against an already-expired row before this sweep ever runs, so this is a
 * backstop for cleanup, not the only enforcement of the expiry boundary —
 * same two-layer pattern as ram-session-cleanup-worker.ts.
 *
 * Unlike RAM's single-file session (consumed immediately by its own
 * /complete route), a Windows Artifact staged file can sit in "staged"
 * status for a while if the operator never submits the rest of the
 * collection — that status is swept here too, not just "uploading".
 */
import { Worker, Job } from "bullmq";
import fs from "fs";
import { getRedisConnection } from "./redis";
import { getWinArtifactsStagedCleanupQueue, type WinArtifactsStagedCleanupJobData } from "./queues";
import { prisma } from "@/lib/db/prisma";

const WIN_ARTIFACTS_STAGED_CLEANUP_QUEUE = "forensicator-winartifacts-staged-cleanup";
const ONE_HOUR_MS = 60 * 60 * 1000;

async function processWinArtifactsStagedCleanup(_job: Job<WinArtifactsStagedCleanupJobData>) {
  const expired = await prisma.windowsArtifactStagedFile.findMany({
    where: { status: { in: ["uploading", "staged"] }, expiresAt: { lt: new Date() } },
    select: { id: true, storagePath: true },
  });

  for (const staged of expired) {
    await fs.promises.unlink(staged.storagePath).catch(() => {});
  }

  if (expired.length > 0) {
    await prisma.windowsArtifactStagedFile.updateMany({
      where: { id: { in: expired.map((s) => s.id) } },
      data: { status: "expired" },
    });
  }

  console.log(`[winartifacts-staged-cleanup] Swept ${expired.length} abandoned staged file(s).`);
  return { swept: expired.length };
}

export function startWinArtifactsStagedCleanupWorker() {
  const worker = new Worker<WinArtifactsStagedCleanupJobData>(WIN_ARTIFACTS_STAGED_CLEANUP_QUEUE, processWinArtifactsStagedCleanup, {
    connection: getRedisConnection(),
    concurrency: 1,
  });
  worker.on("error", (err) => console.error("[winartifacts-staged-cleanup-worker]", err));
  return worker;
}

/**
 * Registers the repeatable schedule — call once at worker startup.
 * Re-adding the same repeat options on every restart is a no-op (BullMQ
 * dedupes repeatable jobs by their jobId), so this is safe to call
 * unconditionally.
 */
export async function scheduleWinArtifactsStagedCleanup() {
  const queue = getWinArtifactsStagedCleanupQueue();
  await queue.add("sweep", {}, { repeat: { every: ONE_HOUR_MS }, jobId: "winartifacts-staged-cleanup-schedule" });
  await queue.close();
}
