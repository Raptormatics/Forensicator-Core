/**
 * Worker bootstrap — start all BullMQ workers.
 *
 * Run alongside the Next.js dev server:
 *   npx tsx src/lib/jobs/worker.ts
 *
 * Or in production add a second process entry in your Dockerfile / PM2 config.
 *
 * The Enterprise overlay replaces this file with a further-extended version
 * that also starts its own remaining Pro-only workers (SIEM, RAM, RAM
 * session cleanup) — enrichment, URLhaus sync, and PCAP analysis used to be
 * overlay-only too, now native to Core alongside Intelligence and Log
 * Analysis. The AI worker isn't started here at all — it runs inside the
 * main app process via src/instrumentation.ts, not this separate worker
 * process, in both editions.
 */
import { startReportWorker } from "./report-worker";
import { startEnrichmentWorker } from "./enrichment-worker";
import { startUrlhausSyncWorker, scheduleUrlhausSync } from "./urlhaus-sync-worker";
import { startPcapWorker } from "./pcap-worker";

const reportWorker = startReportWorker();
const enrichmentWorker = startEnrichmentWorker();
const urlhausSyncWorker = startUrlhausSyncWorker();
const pcapWorker = startPcapWorker();

console.log("[workers] Report, enrichment, URLhaus sync, and PCAP analysis workers started.");

scheduleUrlhausSync().catch((err) => console.error("[workers] Failed to schedule URLhaus feed sync:", err));

async function gracefulShutdown() {
  console.log("[workers] Shutting down…");
  await Promise.all([reportWorker.close(), enrichmentWorker.close(), urlhausSyncWorker.close(), pcapWorker.close()]);
  process.exit(0);
}

process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT",  gracefulShutdown);
