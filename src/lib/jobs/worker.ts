/**
 * Worker bootstrap — start all BullMQ workers.
 *
 * Run alongside the Next.js dev server:
 *   npx tsx src/lib/jobs/worker.ts
 *
 * Or in production add a second process entry in your Dockerfile / PM2 config.
 *
 * The Enterprise overlay replaces this file with a further-extended version
 * that also starts its own remaining Pro-only worker (SIEM), and restores
 * the URLhaus feed's scheduled auto-sync (startUrlhausSyncWorker/
 * scheduleUrlhausSync — continuous/scheduled community-feed sync is an
 * Enterprise-only capability; Core's URLhaus feed sync is manual-only, see
 * POST /api/intelligence/urlhaus-sync, called directly with no queue/worker
 * involved at all). Enrichment, PCAP analysis, and RAM analysis used to be
 * overlay-only too, now native to Core alongside Intelligence, Log
 * Analysis, and PCAP Analysis. The AI worker isn't started here at all —
 * it runs inside the main app process via src/instrumentation.ts, not this
 * separate worker process, in both editions.
 */
import { startReportWorker } from "./report-worker";
import { startEnrichmentWorker } from "./enrichment-worker";
import { startPcapWorker } from "./pcap-worker";
import { startRamWorker } from "./ram-worker";
import { startRamSessionCleanupWorker, scheduleRamSessionCleanup } from "./ram-session-cleanup-worker";

const reportWorker = startReportWorker();
const enrichmentWorker = startEnrichmentWorker();
const pcapWorker = startPcapWorker();
const ramWorker = startRamWorker();
const ramSessionCleanupWorker = startRamSessionCleanupWorker();

console.log("[workers] Report, enrichment, PCAP analysis, and RAM analysis workers started.");

scheduleRamSessionCleanup().catch((err) => console.error("[workers] Failed to schedule RAM session cleanup:", err));

async function gracefulShutdown() {
  console.log("[workers] Shutting down…");
  await Promise.all([
    reportWorker.close(), enrichmentWorker.close(),
    pcapWorker.close(), ramWorker.close(), ramSessionCleanupWorker.close(),
  ]);
  process.exit(0);
}

process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT",  gracefulShutdown);
