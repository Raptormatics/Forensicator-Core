/**
 * Deterministic host risk scoring — shared by the sync route and the live
 * aggregation fallback so the number (and the tier badge derived from it)
 * are always consistent regardless of which code path produced them.
 *
 * Any critical finding forces the "critical" tier outright, independent of
 * the numeric score — a host with 63 critical findings must never render
 * as anything but critical, no matter how the point weights shake out.
 */
export type HostRiskInputs = {
  criticalCount: number;
  highCount: number;
  iocMatchCount: number;
  persistenceEvents: number;
  usbActivity: number;
};

export type RiskTier = "critical" | "high" | "medium" | "low" | "none";

export function computeRiskScore(h: HostRiskInputs): number {
  const score =
    h.criticalCount * 20 +
    h.highCount * 8 +
    h.iocMatchCount * 3 +
    h.persistenceEvents * 10 +
    h.usbActivity * 4;
  return Math.min(100, Math.round(score));
}

export function riskTier(score: number, criticalCount: number): RiskTier {
  if (criticalCount > 0 || score >= 80) return "critical";
  if (score >= 50) return "high";
  if (score >= 20) return "medium";
  if (score > 0) return "low";
  return "none";
}
