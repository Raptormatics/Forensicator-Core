"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, CheckCircle2, ChevronDown, ChevronRight, Clock,
  ClipboardCopy, FileSpreadsheet, Globe, Hash, Loader2, Network, RefreshCw,
  ScrollText, Search, Shield, Terminal, User, Zap,
} from "lucide-react";
import { UploadEnrichButton } from "@/components/intelligence/upload-enrich-button";
import { CaseBadge } from "@/components/cases/case-badge";
import { ArchiveButton, ArchivedPill } from "@/components/cases/archive-button";

// ── Types ──────────────────────────────────────────────────────────────────

type Upload = {
  case: { id: string; caseSeq: number; title: string; status: string; archivedAt: string | null } | null;
  archivedAt: string | null;
  id: string; filename: string; sourceType: string; status: string;
  eventCount: number; findingCount: number; hostname: string | null;
  assetName: string | null; errorMessage: string | null; createdAt: string;
  organization: { name: string } | null;
};

type Finding = {
  id: string; title: string; description: string | null; severity: string;
  eventCount: number; firstSeen: string | null; lastSeen: string | null;
  matchedField: string | null; matchedValue: string | null;
  rule: { id: string; name: string; tags: string[] } | null;
};

type Ioc = { id: string; type: string; value: string; count: number };

type Event = {
  id: string; lineNumber: number; timestamp: string | null; sourceApp: string;
  eventType: string | null; srcIp: string | null; dstIp: string | null;
  httpMethod: string | null; statusCode: number | null; url: string | null;
  username: string | null; process: string | null; message: string | null;
  normalized: Record<string, unknown>;
};

type Tab = "findings" | "iocs" | "events";

// ── Helpers ────────────────────────────────────────────────────────────────

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-900/40 text-red-400 border-red-900",
  high:     "bg-orange-900/40 text-orange-400 border-orange-900",
  medium:   "bg-yellow-900/40 text-yellow-400 border-yellow-900",
  low:      "bg-blue-900/40 text-blue-400 border-blue-900",
  info:     "bg-zinc-800 text-zinc-400 border-zinc-700",
};

const IOC_ICON: Record<string, React.ReactNode> = {
  ip:         <Network className="h-3.5 w-3.5" />,
  domain:     <Globe className="h-3.5 w-3.5" />,
  url:        <Globe className="h-3.5 w-3.5" />,
  hash_md5:   <Hash className="h-3.5 w-3.5" />,
  hash_sha1:  <Hash className="h-3.5 w-3.5" />,
  hash_sha256:<Hash className="h-3.5 w-3.5" />,
  process:    <Terminal className="h-3.5 w-3.5" />,
  filepath:   <Terminal className="h-3.5 w-3.5" />,
  username:   <User className="h-3.5 w-3.5" />,
  email:      <User className="h-3.5 w-3.5" />,
};

const IOC_COLOR: Record<string, string> = {
  ip:          "bg-blue-900/30 text-blue-300 border-blue-800",
  domain:      "bg-green-900/30 text-green-300 border-green-800",
  url:         "bg-green-900/30 text-green-300 border-green-800",
  hash_md5:    "bg-purple-900/30 text-purple-300 border-purple-800",
  hash_sha1:   "bg-purple-900/30 text-purple-300 border-purple-800",
  hash_sha256: "bg-purple-900/30 text-purple-300 border-purple-800",
  process:     "bg-orange-900/30 text-orange-300 border-orange-800",
  filepath:    "bg-orange-900/30 text-orange-300 border-orange-800",
  username:    "bg-teal-900/30 text-teal-300 border-teal-800",
  email:       "bg-teal-900/30 text-teal-300 border-teal-800",
};

// ── Dynamic column helpers ─────────────────────────────────────────────────

/** Preferred ECS fields in priority order (first match wins up to column budget) */
const PRIORITY_FIELDS = [
  "event.action", "event.outcome", "log.level",
  "source.ip", "destination.ip",
  "source.port", "destination.port",
  "network.transport", "network.application",
  "user.name", "host.name",
  "process.name", "process.command_line",
  "http.request.method", "http.response.status_code", "url.original",
  "rule.name", "event.code", "error.message",
  "file.name", "file.path", "hash.sha256",
  "observer.name", "source.domain", "destination.domain",
  "event.kind", "event.category",
];

const FIELD_LABEL: Record<string, string> = {
  "event.action":             "Action",
  "event.outcome":            "Outcome",
  "event.kind":               "Kind",
  "event.category":           "Category",
  "event.code":               "Code",
  "log.level":                "Level",
  "source.ip":                "Src IP",
  "destination.ip":           "Dst IP",
  "source.port":              "Src Port",
  "destination.port":         "Dst Port",
  "source.domain":            "Src Domain",
  "destination.domain":       "Dst Domain",
  "network.transport":        "Proto",
  "network.application":      "App",
  "user.name":                "User",
  "host.name":                "Host",
  "process.name":             "Process",
  "process.command_line":     "Command",
  "http.request.method":      "Method",
  "http.response.status_code":"Status",
  "url.original":             "URL",
  "rule.name":                "Rule",
  "error.message":            "Error",
  "file.name":                "File",
  "file.path":                "Path",
  "hash.sha256":              "SHA-256",
  "observer.name":            "Observer",
};

function fieldLabel(key: string): string {
  return FIELD_LABEL[key] ?? key.split(".").pop() ?? key;
}

function getVal(norm: Record<string, unknown>, key: string): unknown {
  const v = norm[key];
  if (Array.isArray(v)) return v.join(", ");
  return v;
}

function renderCellValue(key: string, val: unknown): React.ReactNode {
  if (val === null || val === undefined || val === "") return <span className="text-zinc-700">—</span>;
  const s = String(val);

  if (key === "event.outcome") {
    const cls = s === "success" ? "text-teal-400" : s === "failure" ? "text-red-400" : "text-zinc-400";
    return <span className={`font-medium ${cls}`}>{s}</span>;
  }
  if (key === "log.level") {
    const cls: Record<string, string> = { critical: "text-red-400", error: "text-red-400", warning: "text-yellow-400", informational: "text-blue-400", debug: "text-zinc-500" };
    return <span className={cls[s] ?? "text-zinc-400"}>{s}</span>;
  }
  if (key === "http.response.status_code") {
    const n = Number(val);
    return <span className={`font-mono ${n >= 400 ? "text-red-400" : n >= 300 ? "text-yellow-400" : "text-teal-400"}`}>{s}</span>;
  }
  if (key === "source.ip" || key === "destination.ip") {
    return <span className="font-mono text-blue-400">{s}</span>;
  }
  if (key === "source.port" || key === "destination.port") {
    return <span className="font-mono text-slate-400">{s}</span>;
  }
  if (key === "user.name") return <span className="text-teal-400">{s}</span>;
  if (key === "process.name" || key === "process.command_line") {
    return <span className="font-mono text-orange-400 truncate block max-w-[140px]" title={s}>{s}</span>;
  }
  if (key === "url.original" || key === "file.path" || key === "process.command_line") {
    return <span className="font-mono text-xs text-zinc-400 truncate block max-w-[180px]" title={s}>{s}</span>;
  }
  if (key === "hash.sha256") {
    return <span className="font-mono text-purple-400 truncate block max-w-[100px]" title={s}>{s.slice(0, 12)}…</span>;
  }
  if (key === "network.transport") return <span className="font-mono text-sky-400 uppercase">{s}</span>;
  if (key === "http.request.method") return <span className="font-mono text-teal-300">{s}</span>;
  return <span className="text-zinc-300 truncate block max-w-[160px]" title={s}>{s}</span>;
}

/** Pick the best dynamic columns from the current event batch (max 5) */
function computeDynamicColumns(events: Event[]): string[] {
  if (events.length === 0) return ["source.ip", "user.name", "event.action", "event.outcome"];
  // Count how many events have each field populated
  const counts: Record<string, number> = {};
  for (const ev of events) {
    for (const [k, v] of Object.entries(ev.normalized ?? {})) {
      if (v !== null && v !== undefined && v !== "" && !k.startsWith("_") && k !== "event.original" && k !== "message") {
        counts[k] = (counts[k] ?? 0) + 1;
      }
    }
  }
  // Score: priority list position wins; tie-break by frequency
  const scored = Object.keys(counts).map((k) => {
    const pIdx = PRIORITY_FIELDS.indexOf(k);
    return { key: k, priority: pIdx >= 0 ? pIdx : 999, freq: counts[k] };
  });
  scored.sort((a, b) => a.priority - b.priority || b.freq - a.freq);
  return scored.slice(0, 5).map((x) => x.key);
}

/** ECS group prefix → display section label */
const SECTION_ORDER = ["event", "source", "destination", "network", "http", "url", "user", "process", "host", "file", "rule", "log", "observer", "related", "error", "threat"];
function sectionOf(key: string) { return key.split(".")[0] ?? "other"; }

// ── Main Component ──────────────────────────────────────────────────────────

export default function LogUploadDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [upload, setUpload]     = useState<Upload | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [iocs, setIocs]         = useState<Ioc[]>([]);
  const [events, setEvents]     = useState<Event[]>([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [loading, setLoading]   = useState(true);
  const [tab, setTab]           = useState<Tab>("findings");
  const [search, setSearch]     = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [page, setPage]         = useState(1);
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null);
  const [expandTab, setExpandTab]         = useState<"json" | "raw" | "table">("json");
  const [iocFilter, setIocFilter] = useState<string>("all");

  const load = useCallback(async (q = search, p = page) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(p), limit: "100" });
      if (q) params.set("q", q);
      const res  = await fetch(`/api/log-analysis/uploads/${id}?${params}`);
      const data = await res.json();
      setUpload(data.upload ?? null);
      setFindings(data.findings ?? []);
      setIocs(data.iocs ?? []);
      setEvents(data.events?.data ?? []);
      setTotalEvents(data.events?.total ?? 0);
    } finally {
      setLoading(false);
    }
  }, [id, search, page]);

  useEffect(() => { load(); }, [load]);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    setSearch(searchInput);
  }

  const iocTypes = ["all", ...Array.from(new Set(iocs.map((i) => i.type)))];
  const filteredIocs = iocFilter === "all" ? iocs : iocs.filter((i) => i.type === iocFilter);

  const dynamicCols = useMemo(() => computeDynamicColumns(events), [events]);

  const criticalCount  = findings.filter((f) => f.severity === "critical").length;
  const highCount      = findings.filter((f) => f.severity === "high").length;

  if (loading && !upload) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-teal-400" />
      </div>
    );
  }

  if (!upload) {
    return (
      <div className="flex min-h-screen items-center justify-center text-zinc-500">
        Upload not found.
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      {/* Header */}
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
          <div className="flex items-center gap-2 text-sm text-zinc-500 mb-4">
            <Link href="/log-analysis" className="flex items-center gap-1.5 hover:text-zinc-300">
              <ArrowLeft className="h-3.5 w-3.5" /> Log Analysis
            </Link>
            <span>/</span>
            <span className="text-zinc-300 truncate max-w-xs">{upload.filename}</span>
          </div>

          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <div className="flex items-center gap-2 text-sm text-teal-200 mb-1">
                <ScrollText className="h-4 w-4" />
                Log Analysis
              </div>
              <h1 className="text-2xl font-semibold text-zinc-50 break-all">{upload.filename}</h1>
              {upload.case && <div className="mt-1 text-sm"><CaseBadge kase={upload.case} showTitle /></div>}
              {/* Only an upload with no case is archived on its own — one in a case goes with its case. */}
              {!upload.case && (
                <div className="mt-2 flex items-center gap-2">
                  {upload.archivedAt && <ArchivedPill />}
                  <ArchiveButton type="log" id={upload.id} action={upload.archivedAt ? "restore" : "archive"} onDone={() => load()} />
                </div>
              )}
              <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-zinc-500">
                <span className="flex items-center gap-1">
                  {upload.status === "ready"
                    ? <CheckCircle2 className="h-3.5 w-3.5 text-teal-400" />
                    : upload.status === "failed"
                    ? <AlertCircle className="h-3.5 w-3.5 text-red-400" />
                    : <Clock className="h-3.5 w-3.5 text-zinc-500" />}
                  <span className="capitalize">{upload.status}</span>
                </span>
                <span>·</span>
                <span>{upload.sourceType}</span>
                {upload.hostname && <><span>·</span><span>{upload.hostname}</span></>}
                {upload.organization && <><span>·</span><span>{upload.organization.name}</span></>}
                <span>·</span>
                <span>{new Date(upload.createdAt).toLocaleString()}</span>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <UploadEnrichButton endpoint={`/api/log-analysis/uploads/${id}/enrich`} />
              <a
                href={`/api/log-analysis/uploads/${id}/export`}
                className="flex items-center gap-1.5 rounded border border-zinc-800 px-3 py-2 text-xs text-zinc-400 hover:text-zinc-200 hover:border-zinc-600"
              >
                <FileSpreadsheet className="h-3.5 w-3.5" /> Export IOCs
              </a>
              <button onClick={() => load()} className="p-2 rounded border border-zinc-800 text-zinc-500 hover:text-zinc-200">
                <RefreshCw className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Summary bar */}
          <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: "Events Parsed",  value: upload.eventCount.toLocaleString(), color: "text-zinc-100" },
              { label: "Findings",       value: upload.findingCount, color: upload.findingCount > 0 ? "text-orange-400" : "text-zinc-100" },
              { label: "Critical / High",value: `${criticalCount} / ${highCount}`,  color: (criticalCount + highCount) > 0 ? "text-red-400" : "text-zinc-100" },
              { label: "IOCs Extracted", value: iocs.length.toLocaleString(),       color: "text-zinc-100" },
            ].map(({ label, value, color }) => (
              <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
                <p className="text-xs text-zinc-500">{label}</p>
                <p className={`mt-1 text-xl font-semibold ${color}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Error message */}
          {upload.errorMessage && (
            <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-900/40 bg-red-950/20 px-4 py-3 text-sm text-red-400">
              <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
              {upload.errorMessage}
            </div>
          )}

          {/* Tabs */}
          <div className="mt-6 flex gap-1 border-b border-zinc-800">
            {([
              { id: "findings", label: "Findings", count: findings.length },
              { id: "iocs",     label: "IOCs",     count: iocs.length },
              { id: "events",   label: "Events",   count: totalEvents },
            ] as { id: Tab; label: string; count: number }[]).map(({ id: tid, label, count }) => (
              <button
                key={tid}
                onClick={() => setTab(tid)}
                className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px ${
                  tab === tid
                    ? "border-teal-400 text-teal-300"
                    : "border-transparent text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {label}
                <span className={`rounded-full px-1.5 py-0.5 text-xs ${
                  tab === tid ? "bg-teal-900/50 text-teal-400" : "bg-zinc-800 text-zinc-500"
                }`}>
                  {count}
                </span>
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Content */}
      <section className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">

        {/* ── FINDINGS TAB ── */}
        {tab === "findings" && (
          findings.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <Shield className="h-10 w-10 text-zinc-600 mb-3" />
              <p className="text-sm text-zinc-400 font-medium">No findings</p>
              <p className="text-xs text-zinc-600 mt-1">No rules matched events in this log file</p>
              <Link href="/log-analysis/rules" className="mt-4 text-sm text-teal-400 hover:text-teal-300">
                Manage Detection Rules →
              </Link>
            </div>
          ) : (
            <div className="space-y-3">
              {findings.map((f) => (
                <div key={f.id} className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
                  <div className="flex items-start gap-3">
                    <span className={`mt-0.5 rounded border px-2 py-0.5 text-xs font-medium capitalize ${SEVERITY_BADGE[f.severity] ?? SEVERITY_BADGE.info}`}>
                      {f.severity}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-zinc-100">{f.title}</p>
                      {f.description && <p className="text-xs text-zinc-500 mt-0.5">{f.description}</p>}
                      <div className="mt-2 flex flex-wrap gap-3 text-xs text-zinc-500">
                        <span className="flex items-center gap-1">
                          <Zap className="h-3 w-3" /> {f.eventCount.toLocaleString()} match{f.eventCount !== 1 ? "es" : ""}
                        </span>
                        {f.matchedField && (
                          <span className="font-mono text-zinc-400">
                            {f.matchedField}: <span className="text-teal-400">{f.matchedValue}</span>
                          </span>
                        )}
                        {f.firstSeen && (
                          <span>{new Date(f.firstSeen).toLocaleString()} – {f.lastSeen ? new Date(f.lastSeen).toLocaleString() : "?"}</span>
                        )}
                      </div>
                    </div>
                    {f.rule && (
                      <div className="shrink-0 flex flex-wrap gap-1">
                        {f.rule.tags.slice(0, 3).map((t) => (
                          <span key={t} className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-500">{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )
        )}

        {/* ── IOCs TAB ── */}
        {tab === "iocs" && (
          <>
            <div className="mb-4 flex flex-wrap gap-2">
              {iocTypes.map((t) => (
                <button
                  key={t}
                  onClick={() => setIocFilter(t)}
                  className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                    iocFilter === t
                      ? "bg-teal-900/50 text-teal-300 border border-teal-700"
                      : "bg-zinc-900 text-zinc-500 border border-zinc-800 hover:border-zinc-700"
                  }`}
                >
                  {t === "all" ? `All (${iocs.length})` : t}
                </button>
              ))}
            </div>
            {filteredIocs.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center">
                <Globe className="h-8 w-8 text-zinc-600 mb-3" />
                <p className="text-sm text-zinc-500">No IOCs found</p>
              </div>
            ) : (
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {filteredIocs.map((ioc) => (
                  <Link
                    key={ioc.id}
                    href={`/intelligence/ioc/${encodeURIComponent(ioc.value)}`}
                    title={`View ${ioc.value} in IOC Intelligence`}
                    className={`flex items-center gap-2.5 rounded-lg border px-3 py-2.5 transition hover:brightness-125 ${IOC_COLOR[ioc.type] ?? "bg-zinc-900 text-zinc-300 border-zinc-800"}`}
                  >
                    {IOC_ICON[ioc.type] ?? <Globe className="h-3.5 w-3.5" />}
                    <span className="font-mono text-xs truncate flex-1">{ioc.value}</span>
                    <span className="shrink-0 text-xs opacity-60">×{ioc.count}</span>
                  </Link>
                ))}
              </div>
            )}
          </>
        )}

        {/* ── EVENTS TAB ── */}
        {tab === "events" && (
          <>
            <form onSubmit={handleSearch} className="mb-4 flex gap-2">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
                <input
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  placeholder="Filter by IP, user, process, URL, message…"
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 py-2 pl-9 pr-3 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
                />
              </div>
              <button type="submit" className="rounded-md border border-zinc-700 bg-zinc-800 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-700">
                Search
              </button>
              {search && (
                <button type="button" onClick={() => { setSearchInput(""); setSearch(""); setPage(1); }}
                  className="rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-500 hover:text-zinc-200">
                  Clear
                </button>
              )}
            </form>

            <p className="text-xs text-zinc-600 mb-3">
              Showing {events.length.toLocaleString()} of {totalEvents.toLocaleString()} events
            </p>

            <div className="rounded-xl border border-zinc-800 overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-900">
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium w-8"></th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium w-10">#</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium whitespace-nowrap">Timestamp</th>
                    {dynamicCols.map((col) => (
                      <th key={col} className="px-3 py-2.5 text-left text-zinc-500 font-medium whitespace-nowrap">
                        {fieldLabel(col)}
                      </th>
                    ))}
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Message</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/50 bg-zinc-950">
                  {events.map((ev) => {
                    const isExpanded = expandedEvent === ev.id;
                    const display = Object.fromEntries(
                      Object.entries(ev.normalized ?? {}).filter(([k]) => !k.startsWith("_"))
                    );
                    const rawLine = String(display["event.original"] ?? "");
                    const displayNoRaw = Object.fromEntries(
                      Object.entries(display).filter(([k]) => k !== "event.original")
                    );
                    return (
                      <>
                        <tr
                          key={ev.id}
                          onClick={() => {
                            if (expandedEvent === ev.id) {
                              setExpandedEvent(null);
                            } else {
                              setExpandedEvent(ev.id);
                              setExpandTab("json");
                            }
                          }}
                          className="cursor-pointer hover:bg-zinc-900/60 transition-colors"
                        >
                          <td className="px-2 py-2 text-zinc-600">
                            {isExpanded
                              ? <ChevronDown className="h-3.5 w-3.5" />
                              : <ChevronRight className="h-3.5 w-3.5" />}
                          </td>
                          <td className="px-3 py-2 text-zinc-600">{ev.lineNumber}</td>
                          <td className="px-3 py-2 text-zinc-500 whitespace-nowrap">
                            {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : "—"}
                          </td>
                          {dynamicCols.map((col) => (
                            <td key={col} className="px-3 py-2">
                              {renderCellValue(col, getVal(ev.normalized ?? {}, col))}
                            </td>
                          ))}
                          <td className="px-3 py-2 text-zinc-400 max-w-[280px]">
                            <span className="truncate block" title={String(ev.message ?? "")}>
                              {ev.message ?? "—"}
                            </span>
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr key={`${ev.id}-expand`} className="bg-zinc-900/40">
                            <td colSpan={4 + dynamicCols.length} className="px-4 py-3">
                              {/* Tab bar */}
                              <div className="flex items-center gap-1 mb-3">
                                {(["json", "raw", "table"] as const).map((t) => (
                                  <button
                                    key={t}
                                    onClick={(e) => { e.stopPropagation(); setExpandTab(t); }}
                                    className={`px-3 py-1 rounded text-xs font-mono font-medium transition-colors ${
                                      expandTab === t
                                        ? "bg-teal-900/60 text-teal-300 border border-teal-700/60"
                                        : "text-zinc-500 hover:text-zinc-300 border border-transparent"
                                    }`}
                                  >
                                    {t.toUpperCase()}
                                  </button>
                                ))}
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    navigator.clipboard.writeText(JSON.stringify(display, null, 2));
                                  }}
                                  className="ml-auto flex items-center gap-1.5 rounded border border-zinc-700 px-2.5 py-1 text-xs text-zinc-500 hover:text-zinc-200 hover:border-zinc-600 transition-colors"
                                >
                                  <ClipboardCopy className="h-3 w-3" /> Copy JSON
                                </button>
                              </div>

                              {/* JSON tab */}
                              {expandTab === "json" && (
                                <pre className="rounded bg-zinc-950 border border-zinc-800 px-4 py-3 font-mono text-xs text-zinc-300 leading-relaxed overflow-x-auto whitespace-pre-wrap break-words">
                                  {JSON.stringify(displayNoRaw, null, 2)}
                                </pre>
                              )}

                              {/* RAW tab */}
                              {expandTab === "raw" && (
                                <pre className="rounded bg-zinc-950 border border-zinc-800 px-4 py-3 font-mono text-xs text-zinc-400 leading-relaxed overflow-x-auto whitespace-pre-wrap break-all">
                                  {rawLine || "(no raw line available)"}
                                </pre>
                              )}

                              {/* TABLE tab */}
                              {expandTab === "table" && (
                                <div className="rounded border border-zinc-800 overflow-hidden">
                                  <table className="w-full text-xs">
                                    <thead>
                                      <tr className="bg-zinc-900 border-b border-zinc-800">
                                        <th className="px-3 py-2 text-left text-zinc-500 font-medium w-1/3">Field</th>
                                        <th className="px-3 py-2 text-left text-zinc-500 font-medium">Value</th>
                                      </tr>
                                    </thead>
                                    <tbody className="divide-y divide-zinc-800/50">
                                      {Object.entries(displayNoRaw)
                                        .sort(([a], [b]) => {
                                          const sa = SECTION_ORDER.indexOf(sectionOf(a));
                                          const sb = SECTION_ORDER.indexOf(sectionOf(b));
                                          return (sa < 0 ? 999 : sa) - (sb < 0 ? 999 : sb) || a.localeCompare(b);
                                        })
                                        .map(([k, v]) => (
                                          <tr key={k} className="hover:bg-zinc-900/40">
                                            <td className="px-3 py-1.5 font-mono text-teal-600 align-top">{k}</td>
                                            <td className="px-3 py-1.5 font-mono text-zinc-300 break-all">
                                              {Array.isArray(v)
                                                ? v.join(", ")
                                                : typeof v === "object" && v !== null
                                                ? JSON.stringify(v)
                                                : String(v)}
                                            </td>
                                          </tr>
                                        ))}
                                    </tbody>
                                  </table>
                                </div>
                              )}
                            </td>
                          </tr>
                        )}
                      </>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalEvents > 100 && (
              <div className="mt-4 flex items-center justify-center gap-3">
                <button
                  onClick={() => { setPage((p) => Math.max(1, p - 1)); load(search, page - 1); }}
                  disabled={page === 1}
                  className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:bg-zinc-800 disabled:opacity-40"
                >
                  Previous
                </button>
                <span className="text-xs text-zinc-500">Page {page}</span>
                <button
                  onClick={() => { setPage((p) => p + 1); load(search, page + 1); }}
                  disabled={events.length < 100}
                  className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:bg-zinc-800 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}
