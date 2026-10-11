"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { RefreshCw, ShieldAlert, ChevronDown, ChevronUp, Zap } from "lucide-react";
import { normalizeSeverity, severityRank, severityClassName, SEVERITY_LABELS } from "@/lib/severity";
import { formatCaseNumber } from "@/lib/cases/case-number";

type SigmaHit = {
  findingDbId:           string;
  investigationId:       string;
  investigationTitle:    string;
  investigationHostname: string | null;
  hostname:              string | null;
  ruleTitle:             string;
  ruleLevel:             string; // mapped priority label
  ruleLevelRaw:          string; // original sigma level
  ruleTags:              string | null;
  ruleFile:              string | null;
  eventId:               string | null;
  user:                  string | null;
  process:               string | null;
  commandLine:           string | null;
  logName:               string | null;
  message:               string | null;
  ruleId:                string | null;
  time:                  string | null;
};

function LevelBadge({ level }: { level: string }) {
  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${severityClassName(level)}`}>
      {normalizeSeverity(level)}
    </span>
  );
}

type CaseOption = { id: string; caseSeq: number; title: string };

export default function SigmaIntelligencePage() {
  const [hits, setHits]       = useState<SigmaHit[]>([]);
  const [total, setTotal]     = useState(0);
  const [loading, setLoading] = useState(true);
  const [q, setQ]             = useState("");
  const [level, setLevel]     = useState("");
  const [caseId, setCaseId]   = useState("");
  const [cases, setCases]     = useState<CaseOption[]>([]);
  const [sort, setSort]       = useState<"time" | "level" | "rule">("time");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<string | null>(null);

  async function load(search = q, lvl = level, cId = caseId) {
    setLoading(true);
    const params = new URLSearchParams({ limit: "500" });
    if (search) params.set("q", search);
    if (lvl) params.set("level", lvl);
    if (cId) params.set("caseId", cId);
    const res = await fetch(`/api/sigma?${params}`);
    if (res.ok) {
      const data = await res.json();
      setHits(data.hits ?? []);
      setTotal(data.total ?? 0);
    }
    setLoading(false);
  }

  useEffect(() => {
    load();
    fetch("/api/cases")
      .then(r => r.ok ? r.json() : { cases: [] })
      .then(d => setCases((d.cases ?? []).map((c: { id: string; caseSeq: number; title: string }) => ({ id: c.id, caseSeq: c.caseSeq, title: c.title }))));
  }, []);

  async function handleSync() {
    setSyncing(true);
    setSyncMsg(null);
    try {
      const res = await fetch("/api/sigma/sync", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      const data = await res.json();
      setSyncMsg(data.message ?? "Done");
      if ((data.updated ?? 0) > 0) load();
    } catch {
      setSyncMsg("Sync failed");
    } finally {
      setSyncing(false);
    }
  }

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    load(q, level);
  }

  function toggleSort(col: "time" | "level" | "rule") {
    if (sort === col) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSort(col); setSortDir("desc"); }
  }

  const sorted = [...hits].sort((a, b) => {
    let cmp = 0;
    if (sort === "level") cmp = severityRank(a.ruleLevel) - severityRank(b.ruleLevel);
    else if (sort === "rule") cmp = a.ruleTitle.localeCompare(b.ruleTitle);
    else cmp = (a.time ?? "").localeCompare(b.time ?? "");
    return sortDir === "asc" ? cmp : -cmp;
  });

  // Stats
  const stats = SEVERITY_LABELS.map((lvl) => ({
    level: lvl,
    count: hits.filter((h) => normalizeSeverity(h.ruleLevel) === lvl).length,
  })).filter((s) => s.count > 0);

  function SortIcon({ col }: { col: "time" | "level" | "rule" }) {
    if (sort !== col) return <ChevronDown className="ml-1 h-3 w-3 opacity-30" />;
    return sortDir === "desc"
      ? <ChevronDown className="ml-1 h-3 w-3 text-teal-400" />
      : <ChevronUp className="ml-1 h-3 w-3 text-teal-400" />;
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* ── Header ── */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-orange-400" />
            Sigma Detections
          </h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            Sigma rule matches collected across all investigations
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleSync}
            disabled={syncing}
            title="Backfill sigma tags on existing findings"
            className="flex items-center gap-1.5 rounded-md border border-zinc-800 px-3 py-2 text-xs text-zinc-400 hover:text-zinc-200 disabled:opacity-50"
          >
            <Zap className="h-3.5 w-3.5" />
            {syncing ? "Syncing…" : "Sync"}
          </button>
          <button onClick={() => load()} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-200">
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>
      {syncMsg && (
        <div className="mb-4 rounded-md border border-teal-400/20 bg-teal-400/5 px-4 py-2 text-sm text-teal-300">
          {syncMsg}
        </div>
      )}

      {/* ── Stat chips ── */}
      {stats.length > 0 && (
        <div className="mb-5 flex flex-wrap gap-2">
          {stats.map((s) => (
            <button
              key={s.level}
              onClick={() => { const next = level === s.level ? "" : s.level; setLevel(next); load(q, next); }}
              className={[
                "inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold transition",
                severityClassName(s.level),
                level === s.level ? "ring-1 ring-offset-1 ring-offset-zinc-950 ring-teal-400" : "opacity-80 hover:opacity-100",
              ].join(" ")}
            >
              <span className="capitalize">{s.level}</span>
              <span className="rounded-full bg-black/30 px-1.5">{s.count}</span>
            </button>
          ))}
          <span className="self-center text-xs text-zinc-600">{total} total hit{total !== 1 ? "s" : ""}</span>
        </div>
      )}

      {/* ── Filters ── */}
      <div className="mb-4 flex flex-wrap gap-3">
        <form onSubmit={handleSearch} className="flex gap-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search rule, process, user…"
            className="w-72 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
          />
          <button
            type="submit"
            className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 hover:border-zinc-500"
          >
            Search
          </button>
        </form>
        <select
          value={level}
          onChange={(e) => { setLevel(e.target.value); load(q, e.target.value); }}
          className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 outline-none focus:border-teal-500"
        >
          <option value="">All levels</option>
          {SEVERITY_LABELS.map((l) => (
            <option key={l} value={l}>{l}</option>
          ))}
        </select>
        <select
          value={caseId}
          onChange={(e) => { setCaseId(e.target.value); load(q, level, e.target.value); }}
          className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 outline-none focus:border-teal-500"
        >
          <option value="">All cases</option>
          {cases.map((c) => (
            <option key={c.id} value={c.id}>{formatCaseNumber(c.caseSeq)} — {c.title}</option>
          ))}
        </select>
      </div>

      {/* ── Table ── */}
      {loading ? (
        <div className="text-center py-16 text-zinc-600">Loading sigma hits…</div>
      ) : sorted.length === 0 ? (
        <div className="text-center py-16 text-zinc-600">
          <ShieldAlert className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p>No sigma rule matches found.</p>
          <p className="text-xs mt-1 text-zinc-700">Upload an investigation containing a <code>sigma/</code> folder to populate this page.</p>
        </div>
      ) : (
        <div className="rounded-xl border border-zinc-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/80 text-left">
                <th
                  className="cursor-pointer px-4 py-3 font-medium text-zinc-400 hover:text-zinc-200"
                  onClick={() => toggleSort("rule")}
                >
                  <span className="flex items-center">Rule Title <SortIcon col="rule" /></span>
                </th>
                <th
                  className="cursor-pointer px-4 py-3 font-medium text-zinc-400 hover:text-zinc-200"
                  onClick={() => toggleSort("level")}
                >
                  <span className="flex items-center">Level <SortIcon col="level" /></span>
                </th>
                <th className="px-4 py-3 font-medium text-zinc-400">Process</th>
                <th className="px-4 py-3 font-medium text-zinc-400">User</th>
                <th className="px-4 py-3 font-medium text-zinc-400">Event ID</th>
                <th className="px-4 py-3 font-medium text-zinc-400">Log</th>
                <th
                  className="cursor-pointer px-4 py-3 font-medium text-zinc-400 hover:text-zinc-200"
                  onClick={() => toggleSort("time")}
                >
                  <span className="flex items-center">Time <SortIcon col="time" /></span>
                </th>
                <th className="px-4 py-3 font-medium text-zinc-400">Investigation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {sorted.map((hit, idx) => {
                const key = `${hit.findingDbId}-${idx}`;
                const isExpanded = expanded[key];
                const proc = hit.process ?? "";
                const procShort = proc.length > 52 ? `…${proc.slice(-48)}` : proc;

                return (
                  <>
                    <tr
                      key={key}
                      className="bg-zinc-950 hover:bg-zinc-900/70 transition-colors cursor-pointer"
                      onClick={() => setExpanded((prev) => ({ ...prev, [key]: !prev[key] }))}
                    >
                      <td className="px-4 py-3 font-medium text-zinc-100 max-w-xs">
                        <div className="flex items-center gap-1.5">
                          <span className="text-zinc-500 text-xs">{isExpanded ? "▾" : "▸"}</span>
                          {hit.ruleTitle}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <LevelBadge level={hit.ruleLevel} />
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-zinc-400 max-w-[200px] truncate" title={proc}>
                        {procShort || <span className="text-zinc-700">—</span>}
                      </td>
                      <td className="px-4 py-3 text-xs text-zinc-400">
                        {hit.user ?? <span className="text-zinc-700">—</span>}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-zinc-500">
                        {hit.eventId ?? "—"}
                      </td>
                      <td className="px-4 py-3 text-xs text-zinc-500">
                        {hit.logName ?? "—"}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-zinc-500 whitespace-nowrap">
                        {hit.time ?? "—"}
                      </td>
                      <td className="px-4 py-3 text-xs">
                        <Link
                          href={`/investigations/${hit.investigationId}`}
                          className="text-teal-400 hover:text-teal-300"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {hit.investigationTitle.length > 28
                            ? `${hit.investigationTitle.slice(0, 28)}…`
                            : hit.investigationTitle}
                        </Link>
                        {hit.investigationHostname && (
                          <span className="block text-zinc-600">{hit.investigationHostname}</span>
                        )}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr key={`${key}-detail`} className="bg-zinc-900/40">
                        <td colSpan={8} className="px-8 py-4">
                          <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-xs sm:grid-cols-3 lg:grid-cols-4">
                            {hit.commandLine && (
                              <Detail label="Command Line" value={hit.commandLine} mono className="col-span-4" />
                            )}
                            {hit.ruleTags && (
                              <Detail label="ATT&CK Tags" value={hit.ruleTags} className="col-span-2" />
                            )}
                            {hit.ruleFile && (
                              <Detail label="Rule File" value={hit.ruleFile} mono className="col-span-2" />
                            )}
                            {hit.ruleId && (
                              <Detail label="Rule ID" value={hit.ruleId} mono />
                            )}
                            {hit.process && (
                              <Detail label="Full Process Path" value={hit.process} mono className="col-span-2" />
                            )}
                            {hit.message && (
                              <Detail label="Message" value={hit.message} className="col-span-2" />
                            )}
                            <Detail label="Event ID" value={hit.eventId ?? "—"} mono />
                            <Detail label="Log Name" value={hit.logName ?? "—"} />
                            <Detail label="User" value={hit.user ?? "—"} />
                            <Detail label="Time" value={hit.time ?? "—"} mono />
                            {hit.hostname && <Detail label="Host" value={hit.hostname} />}
                          </div>
                          <div className="mt-3">
                            <Link
                              href={`/investigations/${hit.investigationId}`}
                              className="text-xs text-teal-400 hover:text-teal-300 underline underline-offset-2"
                            >
                              View finding in investigation →
                            </Link>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Detail({
  label,
  value,
  mono,
  className,
}: {
  label: string;
  value: string;
  mono?: boolean;
  className?: string;
}) {
  return (
    <div className={className}>
      <span className="block text-zinc-600 mb-0.5">{label}</span>
      <span className={`text-zinc-300 break-all ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  );
}
