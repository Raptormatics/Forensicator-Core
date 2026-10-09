/**
 * BullMQ queue definitions shared between API routes (enqueue) and workers (dequeue).
 *
 * Core-only subset — the Enterprise overlay replaces this file with an
 * extended version that adds the Pro queues (enrichment, SIEM, PCAP, RAM,
 * URLhaus sync, RAM session cleanup). Keep this file's exports additive-only
 * from the overlay's perspective: anything Core exports here, the overlay's
 * version must keep exporting identically, so core workers/routes never need
 * to know which edition they're running in.
 */
import { Queue } from "bullmq";
import { getRedisConnection } from "./redis";

// ── Queue names ──────────────────────────────────────────────────────────────
const REPORT_QUEUE = "forensicator-reports";
const AI_QUEUE      = "forensicator-ai";

// ── Job data shapes ──────────────────────────────────────────────────────────

export type ReportJobData = {
  reportId: string;
  caseId: string;
  type: "executive" | "technical";
  format: "pdf" | "csv" | "json" | "zip";
  requestedById: string;
};

export type AiEnrichmentJobData = {
  findingId: string;
};

// ── Queue factories ───────────────────────────────────────────────────────────

export function getReportQueue() {
  return new Queue<ReportJobData>(REPORT_QUEUE, {
    connection: getRedisConnection(),
    defaultJobOptions: { attempts: 3, backoff: { type: "exponential", delay: 5000 } },
  });
}

export function getAiQueue() {
  return new Queue<AiEnrichmentJobData>(AI_QUEUE, {
    connection: getRedisConnection(),
    // Local CPU inference is slow and single failures are rarely transient
    // (a bad prompt/model response won't fix itself on retry the way a
    // flaky third-party API call might), so this retries less than other
    // queues would.
    defaultJobOptions: { attempts: 1 },
  });
}
