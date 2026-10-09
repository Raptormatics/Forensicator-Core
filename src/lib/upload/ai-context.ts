/**
 * buildInvestigationAIContext
 *
 * Produces a compact, AI-friendly context object from a typed investigation
 * record.  Only fields that carry genuine investigative signal are included —
 * housekeeping details (timezone, operator, collector version, etc.) are
 * intentionally omitted so prompt tokens are not wasted.
 *
 * The returned object is safe to JSON.stringify and inject into any LLM prompt.
 */

import type { InvestigationMetadata } from "@/lib/schemas/upload";
import type { JsonObject } from "@/types/json";

export type AIInvestigationContext = {
  investigation_focus: string;
  tags: string[];
  environment: {
    platform?: string;
    os_version?: string;
    hostname?: string;
    domain?: string;
  };
  detection_summary: {
    total_detections: number;
    ioc_detections: number;
    critical_detections?: number;
    high_detections?: number;
    medium_detections?: number;
    low_detections?: number;
    sigma_detections?: number;
  };
};

/**
 * Build an AI context object from an already-parsed InvestigationMetadata.
 * Pass the raw `metadata` JSONB column value when you have it as a plain
 * object rather than the typed schema output.
 */
export function buildInvestigationAIContext(
  meta: InvestigationMetadata | JsonObject
): AIInvestigationContext {
  const m = meta as InvestigationMetadata;

  const os = (m.os ?? {}) as { platform?: string; version?: string };
  const network = (m.network ?? {}) as { hostname?: string; domain?: string };
  const stats = (m.statistics ?? {}) as {
    total_detections?: number;
    ioc_detections?: number;
    critical_detections?: number;
    high_detections?: number;
    medium_detections?: number;
    low_detections?: number;
    sigma_detections?: number;
  };

  return {
    investigation_focus: m.title ?? "Unknown",
    tags: Array.isArray(m.findingtags) ? m.findingtags : [],
    environment: {
      platform: os.platform,
      os_version: os.version,
      hostname: m.hostname ?? network.hostname,
      domain: network.domain,
    },
    detection_summary: {
      total_detections: stats.total_detections ?? 0,
      ioc_detections: stats.ioc_detections ?? 0,
      critical_detections: stats.critical_detections,
      high_detections: stats.high_detections,
      medium_detections: stats.medium_detections,
      low_detections: stats.low_detections,
      sigma_detections: stats.sigma_detections,
    },
  };
}
