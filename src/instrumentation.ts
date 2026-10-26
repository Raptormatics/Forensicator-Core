/**
 * Next.js instrumentation hook — runs once when the server starts.
 * Used to boot BullMQ workers in the same process as the Next.js app.
 * https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
 *
 * Core-only — the Enterprise overlay replaces this file with an extended
 * version that also starts the Pro workers (enrichment, PCAP, RAM) and the
 * license checker. No license checker here at all: Forensicator Core is
 * free and unrestricted, there's nothing to check.
 */
export async function register() {
  // Only run in the Node.js runtime (not Edge), and only on the server.
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { startReportWorker } = await import("./lib/jobs/report-worker");
    const { startAiWorker }     = await import("./lib/jobs/ai-worker");

    startReportWorker();
    startAiWorker();

    // Bundled decoders/rules changed by this release -> database copies.
    const { syncBuiltinsIfChanged } = await import("./lib/seed/builtin-sync");
    void syncBuiltinsIfChanged();

    console.log("[instrumentation] Report + AI workers started.");
  }
}
