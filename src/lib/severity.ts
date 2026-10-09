// ─────────────────────────────────────────────────────────────────────────────
// Canonical Finding/artifact severity vocabulary.
//
// Findings carry Important/Notable/Interesting/Informational — a scale of
// evidentiary noteworthiness, not danger level. This is deliberately distinct
// from risk scores (Finding.data.risk.level/score) and rule severity
// (Detection Rules, Log Analysis Rules, LogFinding), which correctly stay on
// the classic Critical/High/Medium/Low scale — that's a different concept
// (how dangerous is this reading / how bad is it when a rule fires).
//
// This is the single source of truth for normalizing, ranking, and coloring
// Finding severity — every other independent implementation of this has been
// removed in favor of importing from here.
// ─────────────────────────────────────────────────────────────────────────────

export type SeverityLabel = "Important" | "Notable" | "Interesting" | "Informational";

export const SEVERITY_LABELS: SeverityLabel[] = ["Important", "Notable", "Interesting", "Informational"];

/** Investigations/dashboards filtering for "high severity" — kept as one constant so call sites can't drift apart. */
export const HIGH_SEVERITY_LABELS: SeverityLabel[] = ["Important", "Notable"];

/** Higher = more severe. */
const RANK: Record<SeverityLabel, number> = { Important: 4, Notable: 3, Interesting: 2, Informational: 1 };

/**
 * Normalize any raw severity string — either vocabulary, either casing —
 * onto the canonical native-vocabulary label. Unrecognized input defaults to
 * "Informational" (garbage data is more usefully treated as lowest-tier than
 * surfaced as a mystery category).
 */
export function normalizeSeverity(raw: string | null | undefined): SeverityLabel {
  const s = (raw ?? "").trim().toLowerCase();
  if (s === "important" || s === "critical" || s === "crit") return "Important";
  if (s === "notable" || s === "high") return "Notable";
  if (s === "interesting" || s === "medium" || s === "moderate") return "Interesting";
  return "Informational";
}

/** Higher = more severe. Sort descending for most-severe-first. */
export function severityRank(raw: string | null | undefined): number {
  return RANK[normalizeSeverity(raw)];
}

export function severityClassName(raw: string | null | undefined): string {
  switch (normalizeSeverity(raw)) {
    case "Important":
      return "border-red-400/40 bg-red-500/12 text-red-200";
    case "Notable":
      return "border-orange-400/40 bg-orange-500/12 text-orange-200";
    case "Interesting":
      return "border-amber-400/40 bg-amber-500/12 text-amber-200";
    case "Informational":
      return "border-emerald-400/40 bg-emerald-500/12 text-emerald-200";
  }
}

/** Sort findings/timeline rows most-severe-first. */
export function bySeverityDesc<T>(getSeverity: (item: T) => string | null | undefined) {
  return (a: T, b: T) => severityRank(getSeverity(b)) - severityRank(getSeverity(a));
}
