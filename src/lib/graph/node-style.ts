import type { CSSProperties } from "react";

/** Shared React Flow node styling for case/host/correlation graph nodes —
 * used by both the per-case graph (/cases/[id]/graph) and the cross-case
 * correlation graph (/intelligence/correlations/graph). */
export function nodeStyle(type: string, data: Record<string, unknown>): CSSProperties {
  if (type === "case") return { background: "#1e3a5f", border: "2px solid #3b82f6", borderRadius: 12, padding: "10px 18px", color: "#bfdbfe", fontWeight: "bold" };
  if (type === "host") {
    const risk = (data.riskScore as number) ?? 0;
    const borderColor = risk >= 80 ? "#f87171" : risk >= 60 ? "#fb923c" : risk >= 40 ? "#facc15" : "#4ade80";
    return { background: "#134e4a", border: `2px solid ${borderColor}`, borderRadius: 10, padding: "8px 14px", color: "#f0fdfa" };
  }
  if (type === "correlation") return { background: "#1e1b4b", border: "1px solid #6366f1", borderRadius: 6, padding: "4px 10px", color: "#a5b4fc", fontSize: 11, fontFamily: "monospace" };
  return {};
}

export function miniMapColor(type: string | undefined): string {
  if (type === "case") return "#3b82f6";
  if (type === "host") return "#2dd4bf";
  if (type === "correlation") return "#6366f1";
  return "#52525b";
}
