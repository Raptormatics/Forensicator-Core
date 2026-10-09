import Link from "next/link";
import type { SeverityLabel } from "@/lib/severity";

// ── types ────────────────────────────────────────────────────────────────────

export type SeverityCounts = Record<SeverityLabel, number>;

export type CategoryCount = { category: string; count: number };

const SEVERITY_ORDER: SeverityLabel[] = ["Important", "Notable", "Interesting", "Informational"];

// Severity is a reserved status palette (not a general categorical scale) —
// same fixed mapping used by findings-sidebar.tsx and lib/severity severityClassName.
const SEVERITY_BAR_COLOR: Record<SeverityLabel, string> = {
  Important: "bg-red-500",
  Notable: "bg-orange-400",
  Interesting: "bg-amber-400",
  Informational: "bg-emerald-500",
};

const SEVERITY_DOT_COLOR: Record<SeverityLabel, string> = {
  Important: "bg-red-400",
  Notable: "bg-orange-400",
  Interesting: "bg-amber-400",
  Informational: "bg-emerald-400",
};

const SEVERITY_TEXT_COLOR: Record<SeverityLabel, string> = {
  Important: "text-red-300",
  Notable: "text-orange-300",
  Interesting: "text-amber-300",
  Informational: "text-emerald-300",
};

// ── compact stat strip — always visible, single row, Kibana-style ─────────────

export type StatStripProps = {
  totalFindings: number;
  severityCounts: SeverityCounts;
  iocCount: number;
  sigmaCount: number;
  evidenceCount: number;
};

export function StatStrip({ totalFindings, severityCounts, iocCount, sigmaCount, evidenceCount }: StatStripProps) {
  const metrics: { label: string; value: number; className?: string }[] = [
    { label: "Findings", value: totalFindings },
    { label: "Important", value: severityCounts.Important, className: severityCounts.Important ? SEVERITY_TEXT_COLOR.Important : undefined },
    { label: "Notable", value: severityCounts.Notable, className: severityCounts.Notable ? SEVERITY_TEXT_COLOR.Notable : undefined },
    { label: "IOC Matches", value: iocCount },
    { label: "Sigma Hits", value: sigmaCount },
    { label: "Evidence", value: evidenceCount },
  ];

  return (
    <div className="mb-4 flex flex-wrap items-stretch divide-x divide-zinc-800 rounded-lg border border-zinc-800 bg-zinc-950/50">
      {metrics.map((m) => (
        <div key={m.label} className="flex-1 min-w-[7rem] px-4 py-2.5">
          <p className="text-[11px] uppercase tracking-wide text-zinc-500">{m.label}</p>
          <p className={`font-mono text-lg font-semibold ${m.className ?? "text-zinc-200"}`}>{m.value.toLocaleString()}</p>
        </div>
      ))}
    </div>
  );
}

// ── severity distribution + category breakdown — tucked under a toggle ───────

export type SeverityAndCategoryPanelProps = {
  investigationId: string;
  totalFindings: number;
  severityCounts: SeverityCounts;
  categories: CategoryCount[];
  activeCategory: string | null;
};

export function SeverityAndCategoryPanel({
  investigationId,
  totalFindings,
  severityCounts,
  categories,
  activeCategory,
}: SeverityAndCategoryPanelProps) {
  const base = `/investigations/${investigationId}`;

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div>
        <p className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">Severity Distribution</p>
        <SeverityBar counts={severityCounts} total={totalFindings} />
        <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1.5">
          {SEVERITY_ORDER.filter((k) => severityCounts[k] > 0).map((k) => (
            <span key={k} className="inline-flex items-center gap-1.5 text-xs text-zinc-400">
              <span className={`h-2 w-2 rounded-full ${SEVERITY_DOT_COLOR[k]}`} />
              {k} <span className="font-mono text-zinc-500">{severityCounts[k]}</span>
            </span>
          ))}
        </div>
      </div>

      <div>
        <p className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">By Category</p>
        {categories.length === 0 ? (
          <p className="text-xs text-zinc-600">No categorized findings.</p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            <Link
              href={base}
              className={`rounded-full border px-2.5 py-1 text-xs font-medium transition ${
                !activeCategory
                  ? "border-teal-500/40 bg-teal-500/10 text-teal-200"
                  : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
              }`}
            >
              All
            </Link>
            {categories.map((c) => (
              <Link
                key={c.category}
                href={activeCategory === c.category ? base : `${base}?category=${encodeURIComponent(c.category)}`}
                className={`rounded-full border px-2.5 py-1 text-xs font-medium transition ${
                  activeCategory === c.category
                    ? "border-teal-500/40 bg-teal-500/10 text-teal-200"
                    : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {c.category} <span className="font-mono">{c.count}</span>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SeverityBar({ counts, total }: { counts: SeverityCounts; total: number }) {
  if (total === 0) {
    return <div className="h-2.5 w-full rounded-sm bg-zinc-900" />;
  }
  return (
    <div className="flex h-2.5 w-full gap-[2px] overflow-hidden rounded-sm bg-zinc-950/50">
      {SEVERITY_ORDER.filter((k) => counts[k] > 0).map((k) => {
        const pct = (counts[k] / total) * 100;
        return (
          <div
            key={k}
            className={SEVERITY_BAR_COLOR[k]}
            style={{ width: `${pct}%` }}
            title={`${k}: ${counts[k]} (${pct.toFixed(0)}%)`}
          />
        );
      })}
    </div>
  );
}
