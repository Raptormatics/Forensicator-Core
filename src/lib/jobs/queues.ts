/**
 * BullMQ queue definitions shared between API routes (enqueue) and workers (dequeue).
 *
 * The Enterprise overlay replaces this file with a further-extended version
 * that adds its own remaining Pro-only queue (SIEM) — IOC enrichment,
 * URLhaus feed sync, PCAP analysis, and RAM analysis used to be
 * overlay-only too, now native to Core alongside Intelligence, Log
 * Analysis, and PCAP Analysis (see src/lib/intelligence/,
 * src/lib/pcap-analysis/, src/lib/ram-analysis/).
 * Keep this file's exports additive-only from the overlay's perspective:
 * anything Core exports here, the overlay's version must keep exporting
 * identically, so core workers/routes never need to know which edition
 * they're running in.
 */
import { Queue } from "bullmq";
import { getRedisConnection } from "./redis";

// ── Queue names ──────────────────────────────────────────────────────────────
const REPORT_QUEUE      = "forensicator-reports";
const AI_QUEUE           = "forensicator-ai";
const ENRICHMENT_QUEUE   = "forensicator-enrichment";
const URLHAUS_SYNC_QUEUE = "forensicator-urlhaus-sync";
const PCAP_QUEUE         = "forensicator-pcap";
const RAM_QUEUE          = "forensicator-ram";
const RAM_SESSION_CLEANUP_QUEUE = "forensicator-ram-session-cleanup";

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

export type EnrichmentJobData = {
  iocRecordId: string;
  value: string;
  type: "ip" | "hash" | "url" | "domain" | "email";
  /** Org whose provider keys to prefer — falls back to global env keys when absent. */
  organizationId?: string;
};

export type UrlhausSyncJobData = Record<string, never>;

export type PcapJobData = {
  pcapUploadId: string;
};

export type RamJobData = {
  ramUploadId: string;
};

export type RamSessionCleanupJobData = Record<string, never>;

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

export function getEnrichmentQueue() {
  return new Queue<EnrichmentJobData>(ENRICHMENT_QUEUE, {
    connection: getRedisConnection(),
    defaultJobOptions: { attempts: 2, backoff: { type: "fixed", delay: 10000 } },
  });
}

export function getUrlhausSyncQueue() {
  return new Queue<UrlhausSyncJobData>(URLHAUS_SYNC_QUEUE, {
    connection: getRedisConnection(),
    defaultJobOptions: { attempts: 2, backoff: { type: "exponential", delay: 30000 } },
  });
}

export function getPcapQueue() {
  return new Queue<PcapJobData>(PCAP_QUEUE, {
    connection: getRedisConnection(),
    // Same tier as enrichment: a packet-parsing failure is more likely a
    // missing/broken tshark binary or a malformed capture (deterministic)
    // than a transient error, so this doesn't retry as aggressively as
    // report generation.
    defaultJobOptions: { attempts: 2, backoff: { type: "exponential", delay: 15000 } },
  });
}

export function getRamQueue() {
  return new Queue<RamJobData>(RAM_QUEUE, {
    connection: getRedisConnection(),
    // No automatic retry — per-plugin failures already degrade gracefully
    // inside the processor (see src/lib/ram-analysis/processor.ts), so a
    // whole-job failure is a real problem a blind retry is unlikely to fix,
    // and a full run can take tens of minutes. Same reasoning as the AI
    // queue's attempts:1.
    defaultJobOptions: { attempts: 1 },
  });
}

export function getRamSessionCleanupQueue() {
  return new Queue<RamSessionCleanupJobData>(RAM_SESSION_CLEANUP_QUEUE, {
    connection: getRedisConnection(),
    defaultJobOptions: { attempts: 2, backoff: { type: "exponential", delay: 30000 } },
  });
}
