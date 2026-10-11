"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, CheckCircle2, Clock, Globe, Loader2,
  FileSpreadsheet, MemoryStick, Network, RefreshCw, Shield, Zap,
} from "lucide-react";
import { UploadEnrichButton } from "@/components/intelligence/upload-enrich-button";
import { FindingCard, type Finding } from "@/components/ram-analysis/finding-card";
import { ProcessesPanel, buildProcessTree, type ProcessRow } from "@/components/ram-analysis/process-panel";

// ── Types ──────────────────────────────────────────────────────────────────

type Upload = {
  id: string; filename: string; status: string; errorMessage: string | null;
  fileSize: string; osType: string; osBuild: string | null; osArch: string | null;
  pluginStatus: Record<string, string> | null;
  processCount: number; connectionCount: number; findingCount: number; iocCount: number;
  hostname: string | null; assetName: string | null; ipAddress: string | null;
  createdAt: string;
  organization: { name: string } | null;
};

type ConnectionRow = {
  id: string; protocol: string | null;
  localAddr: string | null; localPort: number | null;
  foreignAddr: string | null; foreignPort: number | null;
  state: string | null; pid: number | null; processName: string | null; created: string | null;
};

type Ioc = { id: string; type: string; value: string; count: number };

type Tab = "overview" | "processes" | "connections" | "findings" | "iocs";

// ── Helpers ────────────────────────────────────────────────────────────────

const PLUGIN_LABEL: Record<string, string> = {
  "windows.info.Info":                "OS detection",
  "windows.pslist.PsList":            "Process list",
  "windows.cmdline.CmdLine":          "Command lines",
  "windows.netscan.NetScan":          "Network connections",
  "windows.malware.malfind.Malfind":  "Injected-code detection",
  "banners.Banners":                  "OS/kernel banner detection",
  "linux.pslist.PsList":              "Process list",
  "linux.psaux.PsAux":                "Command lines",
  "linux.sockstat.Sockstat":          "Network connections",
  "linux.malware.malfind.Malfind":    "Injected-code detection",
  "mac.pslist.PsList":                "Process list",
  "mac.psaux.PsAux":                  "Command lines",
  "mac.netstat.Netstat":              "Network connections",
  "mac.malfind.Malfind":              "Injected-code detection",
  "yara":                             "Custom Yara signatures",
};

const OS_LABEL: Record<string, string> = { windows: "Windows", linux: "Linux", macos: "macOS" };

const IN_FLIGHT_STATUSES = new Set(["queued", "processing"]);

function formatBytes(bytes: string): string {
  const n = Number(bytes);
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

// ── Main Component ──────────────────────────────────────────────────────────

export default function RamUploadDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [upload, setUpload]           = useState<Upload | null>(null);
  const [processes, setProcesses]     = useState<ProcessRow[]>([]);
  const [connections, setConnections] = useState<ConnectionRow[]>([]);
  const [findings, setFindings]       = useState<Finding[]>([]);
  const [iocs, setIocs]               = useState<Ioc[]>([]);
  const [loading, setLoading]         = useState(true);
  const [tab, setTab]                 = useState<Tab>("overview");
  const [highlightPid, setHighlightPid] = useState<number | null>(null);
  const [highlightFindingId, setHighlightFindingId] = useState<string | null>(null);
  const highlightedFindingRef = useRef<HTMLDivElement>(null);
  const [severityFilter, setSeverityFilter] = useState<"critical-high" | null>(null);
  const [exportOpen, setExportOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res  = await fetch(`/api/ram-analysis/uploads/${id}?limit=5000`);
      const data = await res.json();
      setUpload(data.upload ?? null);
      setProcesses(data.processes?.data ?? []);
      setConnections(data.connections ?? []);
      setFindings(data.findings ?? []);
      setIocs(data.iocs ?? []);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  // Poll while the image is still being parsed.
  useEffect(() => {
    if (!upload || !IN_FLIGHT_STATUSES.has(upload.status)) return;
    const interval = setInterval(load, 5_000);
    return () => clearInterval(interval);
  }, [upload, load]);

  useEffect(() => {
    if (tab !== "findings" || highlightFindingId === null) return;
    highlightedFindingRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [tab, highlightFindingId, findings]);

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount     = findings.filter((f) => f.severity === "high").length;
  const displayedFindings = severityFilter === "critical-high"
    ? findings.filter((f) => f.severity === "critical" || f.severity === "high")
    : findings;

  function downloadBlob(filename: string, content: string, mime: string) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function toCsvRow(vals: (string | number | null)[]): string {
    return vals
      .map((v) => {
        const s = v === null || v === undefined ? "" : String(v);
        return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      })
      .join(",");
  }

  function exportProcessTree() {
    downloadBlob(`ram-analysis-${id}-process-tree.json`, JSON.stringify(buildProcessTree(processes), null, 2), "application/json");
  }

  function exportTimeline() {
    const events: { timestamp: string; type: string; description: string }[] = [];
    for (const p of processes) {
      if (p.createTime) events.push({ timestamp: p.createTime, type: "process_start", description: `${p.name} (PID ${p.pid})` });
    }
    for (const c of connections) {
      if (c.created) events.push({ timestamp: c.created, type: "connection", description: `${c.protocol ?? "?"} ${c.localAddr ?? "?"}:${c.localPort ?? "?"} -> ${c.foreignAddr ?? "?"}:${c.foreignPort ?? "?"}` });
    }
    for (const f of findings) {
      if (f.firstSeen) events.push({ timestamp: f.firstSeen, type: "finding_first_seen", description: f.title });
      if (f.lastSeen && f.lastSeen !== f.firstSeen) events.push({ timestamp: f.lastSeen, type: "finding_last_seen", description: f.title });
    }
    events.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const csv = ["Timestamp,Type,Description", ...events.map((e) => toCsvRow([e.timestamp, e.type, e.description]))].join("\n");
    downloadBlob(`ram-analysis-${id}-timeline.csv`, csv, "text/csv");
  }

  function exportInjectedVads() {
    const rows = ["PID,Process,VAD Tag,Protection,Start Address,End Address,Commit Charge,Private Memory"];
    for (const f of findings) {
      for (const r of f.malfindRegions) {
        rows.push(toCsvRow([f.pid, f.processName, r.tag, r.protection, r.startAddress, r.endAddress, r.commitCharge, r.privateMemory]));
      }
    }
    downloadBlob(`ram-analysis-${id}-injected-vads.csv`, rows.join("\n"), "text/csv");
  }

  const degradedPlugins = Object.entries(upload?.pluginStatus ?? {}).filter(([, status]) => status !== "ok");

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
            <Link href="/ram-analysis" className="flex items-center gap-1.5 hover:text-zinc-300">
              <ArrowLeft className="h-3.5 w-3.5" /> RAM Analysis
            </Link>
            <span>/</span>
            <span className="text-zinc-300 truncate max-w-xs">{upload.filename}</span>
          </div>

          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <div className="flex items-center gap-2 text-sm text-teal-200 mb-1">
                <MemoryStick className="h-4 w-4" />
                RAM Analysis
              </div>
              <h1 className="text-2xl font-semibold text-zinc-50 break-all">{upload.filename}</h1>
              <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-zinc-500">
                <span className="flex items-center gap-1">
                  {upload.status === "ready"
                    ? <CheckCircle2 className="h-3.5 w-3.5 text-teal-400" />
                    : upload.status === "failed"
                    ? <AlertCircle className="h-3.5 w-3.5 text-red-400" />
                    : upload.status === "processing"
                    ? <Loader2 className="h-3.5 w-3.5 animate-spin text-yellow-400" />
                    : <Clock className="h-3.5 w-3.5 text-zinc-500" />}
                  <span className="capitalize">{upload.status}</span>
                </span>
                <span>·</span>
                <span className="rounded border border-zinc-700 px-1.5 py-0.5 text-zinc-400">{OS_LABEL[upload.osType] ?? upload.osType}</span>
                {upload.osBuild && <><span>·</span><span>{upload.osBuild}{upload.osArch ? ` (${upload.osArch})` : ""}</span></>}
                {upload.hostname && <><span>·</span><span>{upload.hostname}</span></>}
                {upload.organization && <><span>·</span><span>{upload.organization.name}</span></>}
                <span>·</span>
                <span>{new Date(upload.createdAt).toLocaleString()}</span>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <UploadEnrichButton endpoint={`/api/ram-analysis/uploads/${id}/enrich`} />
              <div className="relative">
                <button
                  onClick={() => setExportOpen((v) => !v)}
                  className="flex items-center gap-1.5 rounded border border-zinc-800 px-3 py-2 text-xs text-zinc-400 hover:text-zinc-200 hover:border-zinc-600"
                >
                  <FileSpreadsheet className="h-3.5 w-3.5" /> Export
                </button>
                {exportOpen && (
                  <>
                    <div className="fixed inset-0 z-10" onClick={() => setExportOpen(false)} />
                    <div className="absolute right-0 z-20 mt-1 w-56 rounded-lg border border-zinc-800 bg-zinc-900 py-1 shadow-xl">
                      <a
                        href={`/api/ram-analysis/uploads/${id}/export`}
                        onClick={() => setExportOpen(false)}
                        className="block px-3 py-2 text-xs text-zinc-300 hover:bg-zinc-800"
                      >
                        Full Export (.xlsx)
                      </a>
                      <button
                        onClick={() => { exportTimeline(); setExportOpen(false); }}
                        className="block w-full px-3 py-2 text-left text-xs text-zinc-300 hover:bg-zinc-800"
                      >
                        Export Timeline (.csv)
                      </button>
                      <button
                        onClick={() => { exportProcessTree(); setExportOpen(false); }}
                        className="block w-full px-3 py-2 text-left text-xs text-zinc-300 hover:bg-zinc-800"
                      >
                        Export Process Tree (.json)
                      </button>
                      <button
                        onClick={() => { exportInjectedVads(); setExportOpen(false); }}
                        className="block w-full px-3 py-2 text-left text-xs text-zinc-300 hover:bg-zinc-800"
                      >
                        Export Injected VADs (.csv)
                      </button>
                    </div>
                  </>
                )}
              </div>
              <button onClick={() => load()} className="p-2 rounded border border-zinc-800 text-zinc-500 hover:text-zinc-200">
                <RefreshCw className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Summary bar */}
          <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: "Image Size",     value: formatBytes(upload.fileSize),                 color: "text-zinc-100" },
              { label: "Processes",      value: upload.processCount.toLocaleString(),          color: "text-zinc-100" },
              { label: "Findings",       value: upload.findingCount, color: upload.findingCount > 0 ? "text-orange-400" : "text-zinc-100" },
            ].map(({ label, value, color }) => (
              <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
                <p className="text-xs text-zinc-500">{label}</p>
                <p className={`mt-1 text-xl font-semibold ${color}`}>{value}</p>
              </div>
            ))}
            <button
              onClick={() => { setTab("findings"); setSeverityFilter("critical-high"); }}
              className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3 text-left hover:border-zinc-600"
              title={`${criticalCount + highCount} RamFinding rows at critical/high severity (post-grouping — not a count of affected processes). Click to filter the Findings tab.`}
            >
              <p className="text-xs text-zinc-500">Critical / High</p>
              <p className={`mt-1 text-xl font-semibold ${(criticalCount + highCount) > 0 ? "text-red-400" : "text-zinc-100"}`}>
                {criticalCount} / {highCount}
              </p>
            </button>
          </div>

          {IN_FLIGHT_STATUSES.has(upload.status) && (
            <div className="mt-4 flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/60 px-4 py-3 text-sm text-zinc-400">
              <Loader2 className="h-4 w-4 animate-spin text-yellow-400" />
              {upload.status === "queued" ? "Waiting for a worker to pick up this image…" : "Running Volatility3 plugins — this can take anywhere from minutes to over an hour depending on image size…"}
            </div>
          )}

          {upload.status === "ready" && degradedPlugins.length > 0 && (
            <div className="mt-4 flex items-start gap-2 rounded-lg border border-yellow-900/40 bg-yellow-950/20 px-4 py-3 text-sm text-yellow-400">
              <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
              <div>
                <p className="font-medium">Some data is incomplete</p>
                <p className="text-xs text-yellow-500/80 mt-0.5">
                  {degradedPlugins.map(([plugin, status]) => `${PLUGIN_LABEL[plugin] ?? plugin} ${
                    status === "timeout" ? "timed out" : status === "not_installed" ? "skipped — yara-python not installed" : "failed"
                  }`).join(" · ")}
                </p>
              </div>
            </div>
          )}

          {upload.errorMessage && (
            <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-900/40 bg-red-950/20 px-4 py-3 text-sm text-red-400">
              <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
              <div>
                <p>{upload.errorMessage}</p>
                {upload.osType !== "windows" && (
                  <Link href="/ram-analysis/symbols" className="mt-1 inline-block text-xs text-red-300 underline hover:text-red-200">
                    Manage Symbol Tables →
                  </Link>
                )}
              </div>
            </div>
          )}

          {/* Tabs */}
          <div className="mt-6 flex gap-1 border-b border-zinc-800 overflow-x-auto">
            {([
              { id: "overview",    label: "Overview",    count: null },
              { id: "processes",   label: "Processes",   count: upload.processCount },
              { id: "connections", label: "Connections", count: upload.connectionCount },
              { id: "findings",    label: "Findings",    count: findings.length },
              { id: "iocs",        label: "IOCs",        count: iocs.length },
            ] as { id: Tab; label: string; count: number | null }[]).map(({ id: tid, label, count }) => (
              <button
                key={tid}
                onClick={() => setTab(tid)}
                className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px whitespace-nowrap ${
                  tab === tid
                    ? "border-teal-400 text-teal-300"
                    : "border-transparent text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {label}
                {count !== null && (
                  <span className={`rounded-full px-1.5 py-0.5 text-xs ${
                    tab === tid ? "bg-teal-900/50 text-teal-400" : "bg-zinc-800 text-zinc-500"
                  }`}>
                    {count}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Content */}
      <section className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">

        {/* ── OVERVIEW TAB ── */}
        {tab === "overview" && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h3 className="text-sm font-semibold text-zinc-200 mb-3">Image Details</h3>
              <dl className="space-y-2 text-xs">
                {[
                  ["Filename", upload.filename],
                  ["OS build", upload.osBuild ?? "—"],
                  ["Architecture", upload.osArch ?? "—"],
                  ["Asset", upload.assetName ?? "—"],
                  ["IP address", upload.ipAddress ?? "—"],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-4">
                    <dt className="text-zinc-500">{k}</dt>
                    <dd className="text-zinc-300 text-right break-all">{v}</dd>
                  </div>
                ))}
              </dl>
            </div>
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h3 className="text-sm font-semibold text-zinc-200 mb-3">Plugin Status</h3>
              <dl className="space-y-2 text-xs">
                {Object.entries(upload.pluginStatus ?? {}).map(([plugin, status]) => (
                  <div key={plugin} className="flex justify-between gap-4">
                    <dt className="text-zinc-500">{PLUGIN_LABEL[plugin] ?? plugin}</dt>
                    <dd className={status === "ok" ? "text-teal-400" : "text-yellow-400"}>{status.replace(/_/g, " ")}</dd>
                  </div>
                ))}
                {Object.keys(upload.pluginStatus ?? {}).length === 0 && (
                  <p className="text-zinc-600">No plugin status recorded yet.</p>
                )}
              </dl>
            </div>
          </div>
        )}

        {/* ── PROCESSES TAB ── */}
        {tab === "processes" && (
          <ProcessesPanel
            processes={processes}
            findings={findings}
            highlightPid={highlightPid}
            onJumpToFinding={(findingId) => { setTab("findings"); setHighlightFindingId(findingId); }}
          />
        )}

        {/* ── CONNECTIONS TAB ── */}
        {tab === "connections" && (
          connections.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <Network className="h-10 w-10 text-zinc-600 mb-3" />
              <p className="text-sm text-zinc-400 font-medium">No network connections extracted</p>
            </div>
          ) : (
            <div className="rounded-xl border border-zinc-800 overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-900">
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Protocol</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Local</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Foreign</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">State</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Process</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/50 bg-zinc-950">
                  {connections.map((c) => (
                    <tr key={c.id} className="hover:bg-zinc-900/60 transition-colors">
                      <td className="px-3 py-2 font-mono text-sky-400 uppercase">{c.protocol ?? "—"}</td>
                      <td className="px-3 py-2 font-mono text-zinc-400">{c.localAddr ?? "—"}{c.localPort ? `:${c.localPort}` : ""}</td>
                      <td className="px-3 py-2 font-mono text-blue-400">{c.foreignAddr ?? "—"}{c.foreignPort ? `:${c.foreignPort}` : ""}</td>
                      <td className="px-3 py-2 text-zinc-400">{c.state ?? "—"}</td>
                      <td className="px-3 py-2 text-zinc-300">{c.processName ?? "—"}{c.pid ? ` (${c.pid})` : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        )}

        {/* ── FINDINGS TAB ── */}
        {tab === "findings" && (
          findings.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <Shield className="h-10 w-10 text-zinc-600 mb-3" />
              <p className="text-sm text-zinc-400 font-medium">No findings</p>
              <p className="text-xs text-zinc-600 mt-1">No heuristics or rules matched this memory image</p>
              <Link href="/ram-analysis/rules" className="mt-4 text-sm text-teal-400 hover:text-teal-300">
                Manage Detection Rules →
              </Link>
            </div>
          ) : (
            <div>
              {severityFilter && (
                <div className="mb-3 flex items-center gap-2">
                  <span className="text-xs text-zinc-500">Showing critical/high severity only</span>
                  <button onClick={() => setSeverityFilter(null)} className="text-xs text-teal-400 hover:text-teal-300">
                    Clear filter
                  </button>
                </div>
              )}
              <div className="space-y-3">
                {displayedFindings.map((f) => (
                  <div
                    key={f.id}
                    ref={f.id === highlightFindingId ? highlightedFindingRef : undefined}
                    className={f.id === highlightFindingId ? "rounded-xl ring-2 ring-teal-600" : undefined}
                  >
                    <FindingCard
                      uploadId={id}
                      f={f}
                      onJumpToProcess={(pid) => { setTab("processes"); setHighlightPid(pid); }}
                    />
                  </div>
                ))}
              </div>
            </div>
          )
        )}

        {/* ── IOCs TAB ── */}
        {tab === "iocs" && (
          iocs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Globe className="h-8 w-8 text-zinc-600 mb-3" />
              <p className="text-sm text-zinc-500">No IOCs found</p>
            </div>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {iocs.map((ioc) => (
                <Link
                  key={ioc.id}
                  href={`/intelligence/ioc/${encodeURIComponent(ioc.value)}`}
                  title={`View ${ioc.value} in IOC Intelligence`}
                  className="flex items-center gap-2.5 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2.5 text-blue-300 transition hover:brightness-125"
                >
                  <Globe className="h-3.5 w-3.5" />
                  <span className="font-mono text-xs truncate flex-1">{ioc.value}</span>
                  <span className="shrink-0 text-xs opacity-60">×{ioc.count}</span>
                </Link>
              ))}
            </div>
          )
        )}
      </section>
    </div>
  );
}
