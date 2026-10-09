"use client";

import { useState } from "react";
import Link from "next/link";
import { Search, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { normalizeSeverity } from "@/lib/severity";

export type FindingNavItem = {
  id: string;
  findingId: string;
  findingType: string;
  category: string;
  severity: string;
  riskScore: number | null;
  evidenceCount: number;
};

type FindingsSidebarProps = {
  investigationId: string;
  findings: FindingNavItem[];
  selectedFindingId: string | null;
};

const SEV_FILTERS = ["All", "Important", "Notable", "Interesting", "Informational"] as const;

const SEV_BAR: Record<string, string> = {
  Important:     "bg-red-500",
  Notable:       "bg-orange-400",
  Interesting:   "bg-amber-400",
  Informational: "bg-emerald-500",
};

const SEV_SCORE: Record<string, string> = {
  Important:     "text-red-400",
  Notable:       "text-orange-400",
  Interesting:   "text-amber-400",
  Informational: "text-emerald-400",
};

export function FindingsSidebar({ investigationId, findings, selectedFindingId }: FindingsSidebarProps) {
  const [filter, setFilter] = useState("");
  const [sevFilter, setSevFilter] = useState<string>("All");

  // Count per severity for the filter chips
  const sevCounts = SEV_FILTERS.slice(1).reduce<Record<string, number>>((acc, s) => {
    acc[s] = findings.filter((f) => normalizeSeverity(f.severity) === s).length;
    return acc;
  }, {});

  const filtered = findings.filter((f) => {
    if (sevFilter !== "All" && normalizeSeverity(f.severity) !== sevFilter) return false;
    if (filter.trim()) {
      const q = filter.trim().toLowerCase();
      return f.findingType.toLowerCase().includes(q) || f.category.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <aside className="rounded-lg border border-zinc-800 bg-zinc-950/55">
      {/* Header */}
      <div className="border-b border-zinc-800 px-4 py-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-zinc-100">Findings</h2>
          <span className="rounded-full bg-zinc-900 px-2 py-0.5 text-[11px] text-zinc-500 border border-zinc-800">
            {findings.length}
          </span>
        </div>
      </div>

      {/* Severity filter chips */}
      <div className="border-b border-zinc-800 px-3 py-2 flex flex-wrap gap-1.5">
        {SEV_FILTERS.map((s) => (
          <button
            key={s}
            onClick={() => setSevFilter(s)}
            className={cn(
              "rounded-full px-2.5 py-0.5 text-[11px] font-medium border transition",
              sevFilter === s
                ? "border-teal-500/40 bg-teal-500/10 text-teal-200"
                : "border-zinc-800 bg-transparent text-zinc-500 hover:text-zinc-300"
            )}
          >
            {s === "All" ? `All` : `${s}${sevCounts[s] ? ` · ${sevCounts[s]}` : ""}`}
          </button>
        ))}
      </div>

      {/* Text search */}
      {findings.length > 8 && (
        <div className="border-b border-zinc-800 px-3 py-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 h-3 w-3 -translate-y-1/2 text-zinc-600" />
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter findings…"
              className="w-full rounded border border-zinc-800 bg-zinc-900/70 py-1 pl-7 pr-6 text-xs text-zinc-300 placeholder-zinc-600 outline-none focus:border-teal-600"
            />
            {filter && (
              <button
                onClick={() => setFilter("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-300"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>
          {(filter || sevFilter !== "All") && (
            <p className="mt-1 text-[10px] text-zinc-600">
              {filtered.length} of {findings.length} shown
            </p>
          )}
        </div>
      )}

      <nav className="analyst-scrollbar max-h-[calc(100vh-16rem)] overflow-auto">
        {filtered.length === 0 ? (
          <p className="py-6 text-center text-xs text-zinc-600">No findings match.</p>
        ) : (
          filtered.map((finding) => {
            const selected = selectedFindingId === finding.id;
            const sev = normalizeSeverity(finding.severity);
            const barColor = SEV_BAR[sev] ?? "bg-zinc-600";
            const scoreColor = SEV_SCORE[sev] ?? "text-zinc-500";

            return (
              <Link
                key={finding.id}
                href={`/investigations/${investigationId}?finding=${finding.id}`}
                className={cn(
                  "flex items-stretch gap-0 border-b border-zinc-800/50 transition last:border-b-0",
                  selected
                    ? "bg-teal-400/8"
                    : "hover:bg-zinc-900/60"
                )}
              >
                {/* Left severity bar */}
                <div className={cn("w-[3px] flex-shrink-0 rounded-l-lg", barColor)} />

                {/* Body */}
                <div className={cn(
                  "flex-1 min-w-0 px-3 py-2.5",
                  selected && "border-l border-teal-400/30"
                )}>
                  {/* Name + score */}
                  <div className="flex items-start justify-between gap-2 mb-0.5">
                    <p className="line-clamp-2 text-[13px] font-medium leading-5 text-zinc-100">
                      {finding.findingType}
                    </p>
                    {finding.riskScore !== null && (
                      <span className={cn("font-mono text-xs font-semibold flex-shrink-0 mt-0.5", scoreColor)}>
                        {finding.riskScore}
                      </span>
                    )}
                  </div>
                  {/* Category + evidence count */}
                  <div className="flex items-center justify-between gap-2 mt-1">
                    <p className="truncate text-[11px] text-zinc-500">{finding.category}</p>
                    {finding.evidenceCount > 0 && (
                      <span className="font-mono text-[10px] text-zinc-600 flex-shrink-0">
                        {finding.evidenceCount.toLocaleString()} ev
                      </span>
                    )}
                  </div>
                </div>
              </Link>
            );
          })
        )}
      </nav>
    </aside>
  );
}
