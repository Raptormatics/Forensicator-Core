/**
 * Worker bootstrap — start all BullMQ workers.
 *
 * Run alongside the Next.js dev server:
 *   npx tsx src/lib/jobs/worker.ts
 *
 * Or in production add a second process entry in your Dockerfile / PM2 config.
 *
 * Core-only — the Enterprise overlay replaces this file with an extended
 * version that also starts the Pro workers (enrichment, SIEM, PCAP, RAM,
 * URLhaus sync, RAM session cleanup). The AI worker isn't started here at
 * all — it runs inside the main app process via src/instrumentation.ts,
 * not this separate worker process, in both editions.
 */
import { startReportWorker } from "./report-worker";

const reportWorker = startReportWorker();

console.log("[workers] Report worker started.");

async function gracefulShutdown() {
  console.log("[workers] Shutting down…");
  await Promise.all([reportWorker.close()]);
  process.exit(0);
}

process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT",  gracefulShutdown);
