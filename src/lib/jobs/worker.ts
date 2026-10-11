/**
 * Worker bootstrap — start all BullMQ workers.
 *
 * Run alongside the Next.js dev server:
 *   npx tsx src/lib/jobs/worker.ts
 *
 * Or in production add a second process entry in your Dockerfile / PM2 config.
 *
 * The Enterprise overlay replaces this file with a further-extended version
 * that also starts its own remaining Pro-only worker (SIEM) — enrichment,
 * URLhaus sync, PCAP analysis, and RAM analysis used to be overlay-only
 * too, now native to Core alongside Intelligence, Log Analysis, and PCAP
 * Analysis. The AI worker isn't started here at all — it runs inside the
 * main app process via src/instrumentation.ts, not this separate worker
 * process, in both editions.
 */
import { startReportWorker } from "./report-worker";
import { startEnrichmentWorker } from "./enrichment-worker";
import { startUrlhausSyncWorker, scheduleUrlhausSync } from "./urlhaus-sync-worker";
import { startPcapWorker } from "./pcap-worker";
import { startRamWorker } from "./ram-worker";
import { startRamSessionCleanupWorker, scheduleRamSessionCleanup } from "./ram-session-cleanup-worker";

const reportWorker = startReportWorker();
const enrichmentWorker = startEnrichmentWorker();
const urlhausSyncWorker = startUrlhausSyncWorker();
const pcapWorker = startPcapWorker();
const ramWorker = startRamWorker();
const ramSessionCleanupWorker = startRamSessionCleanupWorker();

console.log("[workers] Report, enrichment, URLhaus sync, PCAP analysis, and RAM analysis workers started.");

scheduleUrlhausSync().catch((err) => console.error("[workers] Failed to schedule URLhaus feed sync:", err));
scheduleRamSessionCleanup().catch((err) => console.error("[workers] Failed to schedule RAM session cleanup:", err));

async function gracefulShutdown() {
  console.log("[workers] Shutting down…");
  await Promise.all([
    reportWorker.close(), enrichmentWorker.close(), urlhausSyncWorker.close(),
    pcapWorker.close(), ramWorker.close(), ramSessionCleanupWorker.close(),
  ]);
  process.exit(0);
}

process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT",  gracefulShutdown);
