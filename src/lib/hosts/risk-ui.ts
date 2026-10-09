/** Client-safe display metadata for host risk tiers and containment status — shared by the Hosts list and detail pages. */

export type RiskTier = "critical" | "high" | "medium" | "low" | "none";
export type IsolationStatus = "active" | "quarantined" | "offline";

export const RISK_META: Record<RiskTier, { label: string; cls: string }> = {
  critical: { label: "Critical", cls: "border-red-500/40 bg-red-500/15 text-red-400" },
  high:     { label: "High",     cls: "border-orange-500/40 bg-orange-500/15 text-orange-400" },
  medium:   { label: "Medium",   cls: "border-yellow-500/40 bg-yellow-500/15 text-yellow-400" },
  low:      { label: "Low",      cls: "border-blue-500/40 bg-blue-500/15 text-blue-400" },
  none:     { label: "None",     cls: "border-zinc-700 bg-zinc-800/60 text-zinc-600" },
};

export const ISOLATION_LABEL: Record<IsolationStatus, string> = {
  active: "Active",
  quarantined: "Quarantined",
  offline: "Offline",
};

export const ISOLATION_CLASS: Record<IsolationStatus, string> = {
  active: "text-zinc-500",
  quarantined: "text-orange-400",
  offline: "text-zinc-600",
};
