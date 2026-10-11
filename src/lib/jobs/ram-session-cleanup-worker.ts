/**
 * Sweeps abandoned chunked RAM upload sessions (src/prisma/schema.prisma's
 * RamUploadSession) — a tab closed mid-upload, a crashed browser, etc. —
 * whose expiresAt has passed without the session ever reaching /complete or
 * being explicitly cancelled via DELETE. Runs on a repeatable schedule; also
 * a lazy check in the chunk/complete routes rejects requests against an
 * already-expired session before this sweep ever runs, so this is a backstop
 * for cleanup, not the only enforcement of the expiry boundary.
 */
import { Worker, Job } from "bullmq";
import fs from "fs";
import { getRedisConnection } from "./redis";
import { getRamSessionCleanupQueue, type RamSessionCleanupJobData } from "./queues";
import { prisma } from "@/lib/db/prisma";

const RAM_SESSION_CLEANUP_QUEUE = "forensicator-ram-session-cleanup";
const ONE_HOUR_MS = 60 * 60 * 1000;

async function processRamSessionCleanup(_job: Job<RamSessionCleanupJobData>) {
  const expired = await prisma.ramUploadSession.findMany({
    where: { status: "uploading", expiresAt: { lt: new Date() } },
    select: { id: true, storagePath: true },
  });

  for (const session of expired) {
    await fs.promises.unlink(session.storagePath).catch(() => {});
  }

  if (expired.length > 0) {
    await prisma.ramUploadSession.updateMany({
      where: { id: { in: expired.map((s) => s.id) } },
      data: { status: "expired" },
    });
  }

  console.log(`[ram-session-cleanup] Swept ${expired.length} abandoned upload session(s).`);
  return { swept: expired.length };
}

export function startRamSessionCleanupWorker() {
  const worker = new Worker<RamSessionCleanupJobData>(RAM_SESSION_CLEANUP_QUEUE, processRamSessionCleanup, {
    connection: getRedisConnection(),
    concurrency: 1,
  });
  worker.on("error", (err) => console.error("[ram-session-cleanup-worker]", err));
  return worker;
}

/**
 * Registers the repeatable schedule — call once at worker startup.
 * Re-adding the same repeat options on every restart is a no-op (BullMQ
 * dedupes repeatable jobs by their jobId), so this is safe to call
 * unconditionally.
 */
export async function scheduleRamSessionCleanup() {
  const queue = getRamSessionCleanupQueue();
  await queue.add("sweep", {}, { repeat: { every: ONE_HOUR_MS }, jobId: "ram-session-cleanup-schedule" });
  await queue.close();
}
