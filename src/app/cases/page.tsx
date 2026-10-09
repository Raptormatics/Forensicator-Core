"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Plus, Folder, RefreshCw } from "lucide-react";
import { formatCaseNumber } from "@/lib/cases/case-number";

type CaseSummary = {
  id: string;
  caseSeq: number;
  title: string;
  description: string | null;
  status: string;
  severity: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  createdBy: { email: string; name: string | null } | null;
  assignee:  { email: string; name: string | null } | null;
  _count: { investigations: number; notes: number };
};

const STATUS_COLORS: Record<string, string> = {
  open:       "bg-blue-900/40 text-blue-300",
  active:     "bg-teal-900/40 text-teal-300",
  monitoring: "bg-yellow-900/40 text-yellow-300",
  resolved:   "bg-green-900/40 text-green-300",
  closed:     "bg-zinc-800 text-zinc-500",
};

const SEV_COLORS: Record<string, string> = {
  important:     "text-red-400",
  notable:       "text-orange-400",
  interesting:   "text-yellow-400",
  informational: "text-green-400",
  // legacy
  critical: "text-red-400",
  high:     "text-orange-400",
  medium:   "text-yellow-400",
  low:      "text-green-400",
  info:     "text-blue-400",
};

export default function CasesPage() {
  const [cases, setCases]       = useState<CaseSummary[]>([]);
  const [loading, setLoading]   = useState(true);
  const [showNew, setShowNew]   = useState(false);
  const [title, setTitle]       = useState("");
  const [severity, setSeverity] = useState("interesting");
  const [creating, setCreating] = useState(false);
  const [showClosed, setShowClosed] = useState(false);

  async function load() {
    setLoading(true);
    const res = await fetch("/api/cases");
    const data = await res.json();
    setCases(data.cases ?? []);
    setLoading(false);
  }

  useEffect(() => { load(); }, []);

  async function createCase() {
    if (!title.trim()) return;
    setCreating(true);
    await fetch("/api/cases", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ title: title.trim(), severity }),
    });
    setTitle("");
    setSeverity("interesting");
    setShowNew(false);
    setCreating(false);
    load();
  }

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">Cases</h1>
          <p className="text-sm text-zinc-500 mt-0.5">Group related investigations into incident cases</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowClosed((v) => !v)}
            className={`rounded-md border px-3 py-2 text-sm font-medium ${
              showClosed
                ? "border-teal-700 bg-teal-900/30 text-teal-300"
                : "border-zinc-800 text-zinc-500 hover:text-zinc-200 hover:border-zinc-600"
            }`}
          >
            {showClosed ? "Hide closed cases" : "Show closed cases"}
          </button>
          <button onClick={load} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-200 hover:border-zinc-600">
            <RefreshCw className="h-4 w-4" />
          </button>
          <button
            onClick={() => setShowNew((v) => !v)}
            className="flex items-center gap-1.5 rounded-md bg-teal-600 px-3 py-2 text-sm font-medium text-white hover:bg-teal-500"
          >
            <Plus className="h-4 w-4" /> New Case
          </button>
        </div>
      </div>

      {showNew && (
        <div className="mb-6 rounded-xl border border-zinc-800 bg-zinc-900 p-4 flex gap-3 items-end">
          <div className="flex-1">
            <label className="block text-xs text-zinc-400 mb-1">Title</label>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && createCase()}
              placeholder="Case title…"
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-teal-500"
            />
          </div>
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Severity</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-teal-500"
            >
              {["important","notable","interesting","informational"].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
          <button
            onClick={createCase}
            disabled={creating || !title.trim()}
            className="rounded-md bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50"
          >
            {creating ? "Creating…" : "Create"}
          </button>
        </div>
      )}

      {(() => {
        const closedCount = cases.filter((c) => c.status === "closed").length;
        const visibleCases = showClosed ? cases : cases.filter((c) => c.status !== "closed");
        return loading ? (
        <div className="text-center py-16 text-zinc-600">Loading cases…</div>
      ) : visibleCases.length === 0 ? (
        <div className="text-center py-16 text-zinc-600">
          <Folder className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p>
            {cases.length === 0
              ? "No cases yet. Create one to group your investigations."
              : "No open cases."}
          </p>
          {!showClosed && closedCount > 0 && (
            <button
              onClick={() => setShowClosed(true)}
              className="mt-3 text-xs text-teal-400 hover:text-teal-300 underline"
            >
              Show {closedCount} closed case{closedCount !== 1 ? "s" : ""}
            </button>
          )}
        </div>
      ) : (
        <>
        {!showClosed && closedCount > 0 && (
          <button
            onClick={() => setShowClosed(true)}
            className="mb-3 text-xs text-zinc-500 hover:text-teal-400 underline"
          >
            {closedCount} closed case{closedCount !== 1 ? "s" : ""} hidden — show
          </button>
        )}
        <div className="grid gap-3">
          {visibleCases.map((c) => (
            <Link
              key={c.id}
              href={`/cases/${c.id}`}
              className="block rounded-xl border border-zinc-800 bg-zinc-900 p-4 hover:border-teal-700/50 transition-colors"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-xs font-semibold uppercase ${SEV_COLORS[c.severity] ?? "text-zinc-400"}`}>
                      {c.severity}
                    </span>
                    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_COLORS[c.status] ?? "bg-zinc-800 text-zinc-400"}`}>
                      {c.status}
                    </span>
                    {c.tags.map((t) => (
                      <span key={t} className="rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-500">{t}</span>
                    ))}
                  </div>
                  <h2 className="mt-1 text-base font-semibold text-zinc-100 truncate">
                    <span className="text-zinc-500 font-mono text-sm mr-1.5">{formatCaseNumber(c.caseSeq)}</span>
                    {c.title}
                  </h2>
                  {c.description && (
                    <p className="mt-0.5 text-sm text-zinc-500 line-clamp-1">{c.description}</p>
                  )}
                </div>
                <div className="shrink-0 text-right text-xs text-zinc-600 space-y-1">
                  <div>{c._count.investigations} investigation{c._count.investigations !== 1 ? "s" : ""}</div>
                  <div>{new Date(c.updatedAt).toLocaleDateString()}</div>
                </div>
              </div>
            </Link>
          ))}
        </div>
        </>
      );
      })()}
    </div>
  );
}
