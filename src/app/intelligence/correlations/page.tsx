"use client";

import { useEffect, useState, useCallback, type ComponentType } from "react";
import Link from "next/link";
import {
  RefreshCw, GitFork, Play, ChevronDown, ChevronUp, Search, Share2,
  Server, User, Fingerprint, Network, Globe, Link2, Cpu, UserCheck,
  AlertTriangle, Tag, ShieldAlert, Folder, Percent, Waypoints, X,
  MoreVertical, Copy, ShieldOff, ShieldCheck, FolderPlus, Sparkles, Bot, Layers, Boxes,
} from "lucide-react";
import { formatCaseNumber } from "@/lib/cases/case-number";

type KnownIoc = { reputation: number | null; threatType: string | null; malwareFamily: string | null } | null;

type CaseRef = { id: string; title: string; caseSeq: number; severity: string; status: string };
type InvRef = { id: string; title: string; hostname: string | null; status: string };

type Correlation = {
  id: string; // `${correlationType}::${value}`
  correlationType: string;
  value: string;
  confidence: number;
  hosts: string[];
  investigationIds: string[];
  investigations: InvRef[];
  cases: CaseRef[];
  createdAt: string;
  knownIoc: KnownIoc;
  label: "Multi-Host Pivot" | "Cross-Case Persistence" | null;
  isWhitelisted: boolean;
  significant: boolean;
  whyThisMatters: string | null;
  rowCount: number;
};

type Stats = {
  total: number;
  avgConfidence: number;
  distinctEntities: number;
  knownIocMatches: number;
  byType: { type: string; count: number }[];
};

type CaseOption = { id: string; caseSeq: number; title: string; _count: { investigations: number } };

type TypeMeta = { label: string; color: string; bg: string; border: string; icon: ComponentType<{ className?: string }> };

const TYPE_META: Record<string, TypeMeta> = {
  shared_host:         { label: "Shared Host",         color: "text-teal-400",   bg: "bg-teal-500/10",   border: "border-teal-500/30",   icon: Server },
  shared_user:         { label: "Shared User",         color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", icon: User },
  shared_hash:         { label: "Shared Hash",         color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/30", icon: Fingerprint },
  shared_ip:           { label: "Shared IP",           color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", icon: Network },
  shared_domain:       { label: "Shared Domain",       color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30",   icon: Globe },
  shared_url:          { label: "Shared URL",          color: "text-indigo-400", bg: "bg-indigo-500/10", border: "border-indigo-500/30", icon: Link2 },
  shared_process:      { label: "Shared Process",      color: "text-pink-400",   bg: "bg-pink-500/10",   border: "border-pink-500/30",   icon: Cpu },
  shared_account:      { label: "Shared Account",      color: "text-cyan-400",   bg: "bg-cyan-500/10",   border: "border-cyan-500/30",   icon: UserCheck },
  shared_finding_type: { label: "Shared Finding Type", color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    icon: AlertTriangle },
  shared_category:     { label: "Shared Category",     color: "text-zinc-300",   bg: "bg-zinc-500/10",   border: "border-zinc-500/30",   icon: Tag },
};

const ALL_TYPES = Object.keys(TYPE_META);
const DEFAULT_META: TypeMeta = { label: "Correlation", color: "text-zinc-400", bg: "bg-zinc-500/10", border: "border-zinc-500/30", icon: GitFork };

function typeMeta(t: string): TypeMeta {
  return TYPE_META[t] ?? DEFAULT_META;
}

function confidenceBadgeClass(conf: number): string {
  if (conf > 85) return "border-green-600 bg-green-500/10 text-green-400";
  if (conf >= 70) return "border-amber-600 bg-amber-500/10 text-amber-400";
  return "border-zinc-700 bg-zinc-500/10 text-zinc-400";
}

const CONF_PRESETS = [
  { label: "All", value: 0 },
  { label: "70+", value: 70 },
  { label: "85+", value: 85 },
];

const SORT_OPTIONS = [
  { value: "confidence",         label: "Confidence" },
  { value: "createdAt",          label: "Newest" },
  { value: "investigationCount", label: "Most Investigations" },
];

const LIMIT = 25;

type ExplainState = {
  loading: boolean;
  aiInterpretation: string | null;
  aiUnavailableReason: string | null;
  fetched: boolean;
};

export default function CorrelationsPage() {
  const [corrs, setCorrs]     = useState<Correlation[]>([]);
  const [stats, setStats]     = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [total, setTotal]     = useState(0);
  const [page, setPage]       = useState(1);

  const [q, setQ]                 = useState("");
  const [qInput, setQInput]       = useState("");
  const [type, setType]           = useState<string | null>(null);
  const [minConfidence, setMinConfidence] = useState(0);
  const [sortBy, setSortBy]       = useState("confidence");
  const [hostFilter, setHostFilter] = useState<string | null>(null);
  const [hideWhitelisted, setHideWhitelisted] = useState(false);

  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [explain, setExplain]   = useState<Record<string, ExplainState>>({});
  const [toast, setToast]       = useState<string | null>(null);

  const [caseFilter, setCaseFilter] = useState<CaseOption | null>(null);
  const [caseSearchOpen, setCaseSearchOpen] = useState(false);
  const [caseSearch, setCaseSearch]     = useState("");
  const [caseOptions, setCaseOptions]   = useState<CaseOption[]>([]);
  const [caseSearchLoading, setCaseSearchLoading] = useState(false);
  const [running, setRunning]         = useState(false);
  const [runMsg, setRunMsg]           = useState<string | null>(null);

  function showToast(msg: string) {
    setToast(msg);
    setTimeout(() => setToast((cur) => (cur === msg ? null : cur)), 2800);
  }

  const load = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({ page: String(page), limit: String(LIMIT), sortBy });
    if (q) params.set("q", q);
    if (type) params.set("type", type);
    if (minConfidence > 0) params.set("minConfidence", String(minConfidence));
    if (hostFilter) params.set("host", hostFilter);
    if (caseFilter) params.set("caseId", caseFilter.id);
    if (hideWhitelisted) params.set("hideWhitelisted", "1");
    const res = await fetch(`/api/correlations?${params}`);
    if (res.ok) {
      const data = await res.json();
      setCorrs(data.correlations ?? []);
      setStats(data.stats ?? null);
      setTotal(data.total ?? 0);
    }
    setLoading(false);
  }, [page, sortBy, q, type, minConfidence, hostFilter, caseFilter, hideWhitelisted]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!caseSearchOpen) return;
    setCaseSearchLoading(true);
    const q = caseSearch.trim();
    fetch(`/api/cases${q ? `?q=${encodeURIComponent(q)}` : ""}`)
      .then((r) => (r.ok ? r.json() : { cases: [] }))
      .then((d) => setCaseOptions(d.cases ?? []))
      .finally(() => setCaseSearchLoading(false));
  }, [caseSearchOpen, caseSearch]);

  function selectCase(c: CaseOption) {
    setCaseFilter(c);
    setCaseSearchOpen(false);
    setCaseSearch("");
    setRunMsg(null);
    setPage(1);
  }

  function clearCase() {
    setCaseFilter(null);
    setRunMsg(null);
    setPage(1);
  }

  async function runCorrelations() {
    if (!caseFilter) return;
    setRunning(true);
    setRunMsg(null);
    try {
      const res = await fetch("/api/correlations/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ caseId: caseFilter.id }),
      });
      const json = await res.json().catch(() => ({}));
      if (res.ok) {
        setRunMsg(`Found ${json.found ?? 0} correlations across ${json.investigations ?? 0} investigations.`);
        setPage(1);
        await load();
      } else {
        setRunMsg(json.error ?? "Correlation failed.");
      }
    } finally {
      setRunning(false);
    }
  }

  function toggleExpand(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    setQ(qInput);
  }

  async function copyIndicator(corr: Correlation) {
    try {
      await navigator.clipboard.writeText(corr.value);
      showToast(`Copied "${corr.value}" to clipboard.`);
    } catch {
      showToast("Could not copy — clipboard access denied.");
    }
    setMenuOpen(null);
  }

  async function toggleWhitelist(corr: Correlation) {
    setMenuOpen(null);
    if (corr.isWhitelisted) {
      await fetch("/api/correlations/whitelist", {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ correlationType: corr.correlationType, value: corr.value }),
      });
      showToast(`Removed "${corr.value}" from the whitelist.`);
    } else {
      await fetch("/api/correlations/whitelist", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ correlationType: corr.correlationType, value: corr.value }),
      });
      showToast(`Marked "${corr.value}" as known-good.`);
    }
    load();
  }

  async function addToActiveCase(corr: Correlation) {
    setMenuOpen(null);
    if (!caseFilter) return;
    const meta = typeMeta(corr.correlationType);
    const content =
      `Correlation flagged for review: ${meta.label} — ${corr.value}\n` +
      `- Confidence: ${corr.confidence}%\n` +
      `- Hosts: ${corr.hosts.join(", ") || "—"}\n` +
      `- Investigations involved: ${corr.investigationIds.length}\n` +
      (corr.cases.length > 0 ? `- Cases involved: ${corr.cases.map((c) => formatCaseNumber(c.caseSeq)).join(", ")}\n` : "") +
      (corr.knownIoc ? `- Known threat-intel match (reputation ${corr.knownIoc.reputation ?? "?"}/100)\n` : "");
    await fetch(`/api/cases/${caseFilter.id}/notes`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ content }),
    });
    showToast(`Added to ${caseFilter.title} as a note.`);
  }

  async function generateAiInterpretation(corr: Correlation) {
    setExplain((prev) => ({ ...prev, [corr.id]: { loading: true, aiInterpretation: null, aiUnavailableReason: null, fetched: false } }));
    try {
      const res = await fetch("/api/correlations/explain", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ correlationType: corr.correlationType, value: corr.value }),
      });
      const json = await res.json().catch(() => ({}));
      setExplain((prev) => ({
        ...prev,
        [corr.id]: {
          loading: false,
          aiInterpretation: json.aiInterpretation ?? null,
          aiUnavailableReason: json.aiUnavailableReason ?? (res.ok ? null : "Could not generate an interpretation."),
          fetched: true,
        },
      }));
    } catch {
      setExplain((prev) => ({ ...prev, [corr.id]: { loading: false, aiInterpretation: null, aiUnavailableReason: "Request failed.", fetched: true } }));
    }
  }

  const distinctHosts = Array.from(new Set(corrs.flatMap((c) => c.hosts))).slice(0, 12);
  const totalPages = Math.max(1, Math.ceil(total / LIMIT));
  const countsByType = new Map((stats?.byType ?? []).map((t) => [t.type, t.count]));

  return (
    <div className="p-6 max-w-6xl mx-auto" onClick={() => setMenuOpen(null)}>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-teal-500 mb-1">Intelligence</p>
          <h1 className="text-2xl font-bold text-zinc-100">Correlations</h1>
          <p className="text-sm text-zinc-500 mt-0.5">Shared indicators detected across multiple hosts and investigations</p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            href="/intelligence/correlations/graph"
            className="inline-flex items-center gap-1.5 rounded-md border border-zinc-800 px-3 py-2 text-sm text-zinc-400 hover:text-zinc-200 hover:border-zinc-700"
          >
            <Waypoints className="h-4 w-4" /> View Graph
          </Link>
          <button onClick={load} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-200">
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Global case scope filter — view correlations for one case (and run/re-run for it), or clear to see the general cross-case view */}
      <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 mb-6">
        {caseFilter ? (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 min-w-0">
              <Folder className="h-4 w-4 text-teal-400 shrink-0" />
              <div className="min-w-0">
                <p className="text-sm text-zinc-200 truncate">
                  <span className="font-mono text-xs text-zinc-500 mr-1.5">{formatCaseNumber(caseFilter.caseSeq)}</span>
                  {caseFilter.title}
                </p>
                <p className="text-xs text-zinc-600">{caseFilter._count.investigations} investigation{caseFilter._count.investigations !== 1 ? "s" : ""} linked · active case for &ldquo;Add to Active Case&rdquo;</p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={runCorrelations}
                disabled={running || caseFilter._count.investigations < 2}
                title={caseFilter._count.investigations < 2 ? "This case needs at least 2 linked investigations to run correlation" : undefined}
                className="inline-flex items-center gap-1.5 rounded-md bg-teal-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <Play className="h-3.5 w-3.5" /> {running ? "Running…" : stats && stats.total > 0 ? "Re-run Correlation" : "Run Correlation"}
              </button>
              <button onClick={clearCase} className="inline-flex items-center gap-1 rounded-md border border-zinc-800 px-2.5 py-1.5 text-xs text-zinc-500 hover:text-zinc-200">
                <X className="h-3.5 w-3.5" /> Clear
              </button>
            </div>
          </div>
        ) : (
          <div className="relative">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
              <input
                value={caseSearch}
                onChange={(e) => { setCaseSearch(e.target.value); setCaseSearchOpen(true); }}
                onFocus={() => setCaseSearchOpen(true)}
                placeholder="Search a case to view or run correlations for it…"
                className="w-full rounded-md border border-zinc-700 bg-zinc-950 py-2.5 pl-9 pr-3 text-sm text-zinc-200 placeholder-zinc-500 outline-none focus:border-teal-400/60 focus:ring-1 focus:ring-teal-400/20"
              />
            </div>
            <p className="text-xs text-zinc-600 mt-1.5">Showing correlations across every case — useful for spotting attack patterns that persist org-wide. Select a case here to also enable &ldquo;Add to Active Case&rdquo;.</p>

            {caseSearchOpen && (
              <div className="absolute left-0 right-0 top-full z-20 mt-2 rounded-lg border border-zinc-700 bg-zinc-950 shadow-xl overflow-hidden">
                <div className="max-h-64 overflow-y-auto">
                  {caseSearchLoading ? (
                    <p className="px-3 py-4 text-xs text-zinc-600 text-center">Loading…</p>
                  ) : caseOptions.length === 0 ? (
                    <p className="px-3 py-4 text-xs text-zinc-600 text-center">No cases found.</p>
                  ) : (
                    caseOptions.map((c) => (
                      <button
                        key={c.id}
                        onClick={() => selectCase(c)}
                        className="w-full flex items-center justify-between px-3 py-2.5 text-left hover:bg-zinc-800 transition-colors border-b border-zinc-800/50 last:border-0"
                      >
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-zinc-200 truncate">
                            <span className="font-mono text-xs text-zinc-500 mr-1.5">{formatCaseNumber(c.caseSeq)}</span>
                            {c.title}
                          </p>
                        </div>
                        <span className="text-xs text-zinc-500 shrink-0 ml-3">{c._count.investigations} investigation{c._count.investigations !== 1 ? "s" : ""}</span>
                      </button>
                    ))
                  )}
                </div>
                <button onClick={() => setCaseSearchOpen(false)} className="w-full px-3 py-2 text-xs text-zinc-600 hover:text-zinc-300 border-t border-zinc-800">
                  Close
                </button>
              </div>
            )}
          </div>
        )}

        {runMsg && (
          <p className={`text-xs mt-3 rounded px-2 py-1.5 ${runMsg.toLowerCase().includes("fail") || runMsg.toLowerCase().includes("error") || runMsg.toLowerCase().includes("need") ? "bg-red-900/30 text-red-400" : "bg-teal-900/30 text-teal-400"}`}>
            {runMsg}
          </p>
        )}
      </section>

      {/* Stat tiles */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          {[
            { label: "Correlation Points", value: stats.total,            icon: GitFork, color: "text-zinc-300",
              title: "Distinct (type, value) matches where investigations share something — e.g. the same IP counted once per correlation type it qualifies under." },
            { label: "Distinct Entities",  value: stats.distinctEntities, icon: Boxes,   color: "text-blue-400",
              title: "Unique underlying values behind those matches, regardless of correlation type — always ≤ Correlation Points." },
            { label: "Avg Confidence",     value: `${stats.avgConfidence}%`, icon: Percent, color: "text-teal-400", title: undefined },
            { label: "Known IOC Matches",  value: stats.knownIocMatches, icon: ShieldAlert, color: "text-red-400", title: undefined },
          ].map(({ label, value, icon: Icon, color, title }) => (
            <div key={label} className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 text-center" title={title}>
              <Icon className={`h-5 w-5 mx-auto mb-2 ${color}`} />
              <div className={`text-xl font-bold ${color}`}>{value}</div>
              <div className="text-xs text-zinc-500 mt-1">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filter bar — "Search value…" here is strictly a filter on the populated list below, separate from the case-scope search above */}
      <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 mb-4 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <form onSubmit={handleSearch} className="relative flex-1 min-w-[220px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
            <input
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              placeholder="Search value…"
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 pl-8 pr-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
            />
          </form>

          <div className="flex items-center gap-1.5">
            {CONF_PRESETS.map((p) => (
              <button
                key={p.value}
                onClick={() => { setMinConfidence(p.value); setPage(1); }}
                className={`rounded-md px-2.5 py-1.5 text-xs font-medium border ${
                  minConfidence === p.value
                    ? "border-teal-600 bg-teal-500/10 text-teal-400"
                    : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          <button
            onClick={() => { setHideWhitelisted((v) => !v); setPage(1); }}
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium border ${
              hideWhitelisted ? "border-teal-600 bg-teal-500/10 text-teal-400" : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
            }`}
          >
            <ShieldOff className="h-3.5 w-3.5" /> Hide Whitelisted
          </button>

          <select
            value={sortBy}
            onChange={(e) => { setSortBy(e.target.value); setPage(1); }}
            className="rounded-md border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-xs text-zinc-300 outline-none focus:border-teal-500"
          >
            {SORT_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => { setType(null); setPage(1); }}
            className={`rounded-full px-2.5 py-1 text-xs font-medium border ${
              type === null ? "border-zinc-500 bg-zinc-700/40 text-zinc-200" : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
            }`}
          >
            All Types
          </button>
          {ALL_TYPES.map((t) => {
            const meta = typeMeta(t);
            const Icon = meta.icon;
            const active = type === t;
            const count = countsByType.get(t) ?? 0;
            return (
              <button
                key={t}
                onClick={() => { setType(active ? null : t); setPage(1); }}
                className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-medium border ${
                  active ? `${meta.border} ${meta.bg} ${meta.color}` : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
                }`}
              >
                <Icon className="h-3 w-3" /> {meta.label} ({count})
              </button>
            );
          })}
        </div>

        {(hostFilter || distinctHosts.length > 0) && (
          <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-zinc-800/60">
            <span className="text-xs text-zinc-600">Hosts:</span>
            {hostFilter && (
              <button
                onClick={() => { setHostFilter(null); setPage(1); }}
                className="rounded-full border border-teal-600 bg-teal-500/10 px-2.5 py-0.5 text-xs text-teal-400"
              >
                {hostFilter} ×
              </button>
            )}
            {!hostFilter && distinctHosts.map((h) => (
              <button
                key={h}
                onClick={() => { setHostFilter(h); setPage(1); }}
                className="rounded-full border border-zinc-800 px-2.5 py-0.5 text-xs text-zinc-500 hover:text-zinc-300"
              >
                {h}
              </button>
            ))}
          </div>
        )}
      </section>

      {/* Correlation list — grouped by (type, value) so the same entity across cases renders once */}
      {loading ? (
        <div className="text-center py-16 text-zinc-600">Loading correlations…</div>
      ) : corrs.length === 0 ? (
        <div className="text-center py-16 text-zinc-600">
          <GitFork className="h-12 w-12 mx-auto mb-3 opacity-30" />
          {caseFilter ? (
            <>
              <p className="mb-4">No correlations yet for this case.</p>
              <button
                onClick={runCorrelations}
                disabled={running || caseFilter._count.investigations < 2}
                className="inline-flex items-center gap-1.5 rounded-md bg-teal-600 px-3 py-2 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <Play className="h-4 w-4" /> {running ? "Running…" : "Run Correlation"}
              </button>
            </>
          ) : (
            <p>No correlations match these filters. Select a case above to run correlation analysis.</p>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {corrs.map((corr) => {
            const meta = typeMeta(corr.correlationType);
            const Icon = meta.icon;
            const isOpen = expanded.has(corr.id);
            const hostsShown = corr.hosts.slice(0, 6);
            const hostsExtra = corr.hosts.length - hostsShown.length;
            const casesShown = corr.cases.slice(0, 2);
            const casesExtra = corr.cases.length - casesShown.length;
            const ex = explain[corr.id];

            return (
              <div
                key={corr.id}
                className={`rounded-xl border p-4 transition-colors ${
                  corr.isWhitelisted ? "border-zinc-800/60 bg-zinc-900/40 opacity-70" : "border-zinc-800 bg-zinc-900"
                }`}
              >
                <div className="flex items-start justify-between gap-4">
                  <button onClick={() => toggleExpand(corr.id)} className="flex-1 min-w-0 text-left">
                    <div className="flex items-center flex-wrap gap-2 mb-1.5">
                      <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold ${meta.bg} ${meta.color}`}>
                        <Icon className="h-3 w-3" /> {meta.label}
                      </span>
                      <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${confidenceBadgeClass(corr.confidence)}`}>
                        {corr.confidence}%
                      </span>
                      {corr.label && (
                        <span className="inline-flex items-center gap-1 rounded-full border border-indigo-500/30 bg-indigo-500/10 px-2 py-0.5 text-xs font-semibold text-indigo-300">
                          <Layers className="h-3 w-3" /> {corr.label}
                        </span>
                      )}
                      {corr.knownIoc && (
                        <span className="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/15 px-2 py-0.5 text-xs font-bold text-red-400">
                          🛑 Malicious IOC
                          {corr.knownIoc.reputation !== null && ` · ${corr.knownIoc.reputation}/100`}
                        </span>
                      )}
                      {corr.isWhitelisted && (
                        <span className="inline-flex items-center gap-1 rounded-full border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">
                          <ShieldCheck className="h-3 w-3" /> Whitelisted
                        </span>
                      )}
                    </div>
                    <p className="font-mono text-sm text-zinc-200 truncate">{corr.value}</p>
                    <p className="text-xs text-zinc-600 mt-1">
                      Hosts: {hostsShown.join(", ")}{hostsExtra > 0 ? ` +${hostsExtra} more` : ""} · {corr.investigationIds.length} investigation{corr.investigationIds.length !== 1 ? "s" : ""}
                      {corr.cases.length > 0 && (
                        <>
                          {" "}· Cases:{" "}
                          {casesShown.map((c, i) => (
                            <span key={c.id}>
                              <Link
                                href={`/cases/${c.id}`}
                                onClick={(e) => e.stopPropagation()}
                                title={`${c.title} — ${c.severity} · ${c.status}`}
                                className="text-teal-500 hover:text-teal-300"
                              >
                                {formatCaseNumber(c.caseSeq)}
                              </Link>
                              {i < casesShown.length - 1 ? ", " : ""}
                            </span>
                          ))}
                          {casesExtra > 0 ? ` +${casesExtra} more` : ""}
                        </>
                      )}
                    </p>
                  </button>
                  <div className="shrink-0 flex items-center gap-1">
                    <div className="relative">
                      <button
                        onClick={(e) => { e.stopPropagation(); setMenuOpen(menuOpen === corr.id ? null : corr.id); }}
                        className="p-1.5 rounded-md text-zinc-600 hover:text-zinc-200 hover:bg-zinc-800"
                      >
                        <MoreVertical className="h-4 w-4" />
                      </button>
                      {menuOpen === corr.id && (
                        <div
                          onClick={(e) => e.stopPropagation()}
                          className="absolute right-0 top-full z-20 mt-1 w-56 rounded-lg border border-zinc-700 bg-zinc-950 shadow-xl overflow-hidden py-1"
                        >
                          <button
                            onClick={() => addToActiveCase(corr)}
                            disabled={!caseFilter}
                            title={!caseFilter ? "Select a case above to enable this" : undefined}
                            className="w-full flex items-center gap-2 px-3 py-2 text-left text-xs text-zinc-300 hover:bg-zinc-800 disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            <FolderPlus className="h-3.5 w-3.5" /> Add to Active Case
                          </button>
                          <button
                            onClick={() => toggleWhitelist(corr)}
                            className="w-full flex items-center gap-2 px-3 py-2 text-left text-xs text-zinc-300 hover:bg-zinc-800"
                          >
                            {corr.isWhitelisted ? <ShieldOff className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                            {corr.isWhitelisted ? "Un-whitelist" : "Whitelist / Mark Known Good"}
                          </button>
                          <button
                            onClick={() => copyIndicator(corr)}
                            className="w-full flex items-center gap-2 px-3 py-2 text-left text-xs text-zinc-300 hover:bg-zinc-800"
                          >
                            <Copy className="h-3.5 w-3.5" /> Copy Indicator
                          </button>
                          <Link
                            href={`/intelligence/correlations/graph?q=${encodeURIComponent(corr.value)}&type=${corr.correlationType}`}
                            onClick={() => setMenuOpen(null)}
                            className="w-full flex items-center gap-2 px-3 py-2 text-left text-xs text-zinc-300 hover:bg-zinc-800"
                          >
                            <Waypoints className="h-3.5 w-3.5" /> Pivot / View Graph
                          </Link>
                        </div>
                      )}
                    </div>
                    <button onClick={() => toggleExpand(corr.id)} className="text-zinc-600 hover:text-zinc-300 p-1.5">
                      {isOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                <div className={`grid transition-all duration-200 ease-in-out ${isOpen ? "grid-rows-[1fr] opacity-100 mt-3" : "grid-rows-[0fr] opacity-0"}`}>
                  <div className="overflow-hidden">
                    <div className="pt-3 border-t border-zinc-800 space-y-4">
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div>
                          <p className="text-xs font-medium text-zinc-500 mb-1.5">Hosts ({corr.hosts.length})</p>
                          <div className="flex flex-wrap gap-1">
                            {corr.hosts.map((h) => (
                              <button
                                key={h}
                                onClick={() => { setHostFilter(h); setPage(1); }}
                                className="rounded-full border border-zinc-800 px-2 py-0.5 text-xs text-zinc-400 hover:text-zinc-200"
                              >
                                {h}
                              </button>
                            ))}
                          </div>
                        </div>
                        <div>
                          <p className="text-xs font-medium text-zinc-500 mb-1.5">Investigations ({corr.investigationIds.length})</p>
                          <div className="flex flex-wrap gap-1">
                            {corr.investigations.map((inv) => (
                              <Link
                                key={inv.id}
                                href={`/investigations/${inv.id}`}
                                title={`${inv.title} · status: ${inv.status} · id: ${inv.id}`}
                                className="rounded-full border border-zinc-800 px-2 py-0.5 text-xs text-teal-500 hover:text-teal-300 truncate max-w-[160px]"
                              >
                                {inv.hostname ?? inv.title}
                              </Link>
                            ))}
                            {corr.investigationIds.length > corr.investigations.length && (
                              <span className="text-xs text-zinc-600">+{corr.investigationIds.length - corr.investigations.length} more</span>
                            )}
                          </div>
                        </div>
                        <div>
                          <p className="text-xs font-medium text-zinc-500 mb-1.5">Cases ({corr.cases.length})</p>
                          <div className="flex flex-wrap gap-1">
                            {corr.cases.map((c) => (
                              <Link
                                key={c.id}
                                href={`/cases/${c.id}`}
                                title={`${c.title} · severity: ${c.severity} · status: ${c.status}`}
                                className="rounded-full border border-zinc-800 px-2 py-0.5 text-xs text-teal-500 hover:text-teal-300 truncate max-w-[160px]"
                              >
                                {formatCaseNumber(c.caseSeq)}
                              </Link>
                            ))}
                            {corr.cases.length === 0 && <span className="text-xs text-zinc-600">—</span>}
                          </div>
                        </div>
                      </div>

                      {corr.knownIoc && (corr.knownIoc.threatType || corr.knownIoc.malwareFamily) && (
                        <div className="text-xs text-zinc-500">
                          {corr.knownIoc.threatType && <span>Threat type: <span className="text-zinc-300">{corr.knownIoc.threatType}</span></span>}
                          {corr.knownIoc.threatType && corr.knownIoc.malwareFamily && " · "}
                          {corr.knownIoc.malwareFamily && <span>Malware family: <span className="text-zinc-300">{corr.knownIoc.malwareFamily}</span></span>}
                        </div>
                      )}

                      {corr.significant && corr.whyThisMatters && (
                        <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
                          <p className="text-xs font-bold uppercase tracking-wide text-zinc-400 mb-1.5">Why This Matters</p>
                          <p className="text-xs text-zinc-300 leading-relaxed">{corr.whyThisMatters}</p>

                          <div className="mt-3 pt-3 border-t border-zinc-800/70">
                            {!ex?.fetched && !ex?.loading && (
                              <button
                                onClick={() => generateAiInterpretation(corr)}
                                className="inline-flex items-center gap-1.5 rounded-md border border-indigo-700/50 bg-indigo-500/10 px-2.5 py-1.5 text-xs font-medium text-indigo-300 hover:bg-indigo-500/20"
                              >
                                <Sparkles className="h-3.5 w-3.5" /> Generate AI Interpretation
                              </button>
                            )}
                            {ex?.loading && (
                              <p className="text-xs text-zinc-500 flex items-center gap-1.5"><Bot className="h-3.5 w-3.5 animate-pulse" /> Generating interpretation…</p>
                            )}
                            {ex?.fetched && !ex.loading && ex.aiInterpretation && (
                              <div className="rounded-md border border-indigo-700/40 bg-indigo-500/5 p-2.5">
                                <p className="text-[11px] font-semibold uppercase tracking-wide text-indigo-300 mb-1 flex items-center gap-1.5">
                                  <Bot className="h-3 w-3" /> AI Interpretation — unverified
                                </p>
                                <p className="text-xs text-zinc-300 leading-relaxed">{ex.aiInterpretation}</p>
                                <p className="text-[10px] text-zinc-600 mt-1.5">Generated from the deterministic facts above only. May be incomplete or imprecise — treat as a starting hypothesis, not a conclusion.</p>
                              </div>
                            )}
                            {ex?.fetched && !ex.loading && !ex.aiInterpretation && (
                              <p className="text-xs text-zinc-600">{ex.aiUnavailableReason ?? "No interpretation available."}</p>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Pagination */}
      {total > LIMIT && (
        <div className="flex gap-2 mt-4 justify-center items-center">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="rounded px-3 py-1 text-sm border border-zinc-800 text-zinc-500 disabled:opacity-30"
          >
            Previous
          </button>
          <span className="px-3 py-1 text-sm text-zinc-500">Page {page} of {totalPages} · {total} total</span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="rounded px-3 py-1 text-sm border border-zinc-800 text-zinc-500 disabled:opacity-30"
          >
            Next
          </button>
        </div>
      )}

      {!loading && corrs.length > 0 && (
        <div className="flex items-center gap-1.5 mt-4 opacity-60 hover:opacity-100 transition-opacity">
          <Share2 className="h-3 w-3 text-zinc-600" />
          <span className="text-xs text-zinc-600">Powered by 10-dimension cross-investigation correlation, grouped by shared entity. Select a case above to run or re-run analysis for it as new investigations are linked.</span>
        </div>
      )}

      {toast && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-30 rounded-md border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm text-zinc-200 shadow-xl">
          {toast}
        </div>
      )}
    </div>
  );
}
