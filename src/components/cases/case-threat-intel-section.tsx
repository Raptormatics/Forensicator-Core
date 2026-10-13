"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle, CheckCircle, FileSpreadsheet, FileText, Globe, RefreshCw,
  Settings, Shield, Sparkles, Upload, X, XCircle,
} from "lucide-react";

// Case-scoped IOC Management — the Core half of the IOC Management split.
// Always scoped to this case's own id (no case picker, no "all cases"
// option — that cross-case view is the Enterprise differentiator, see
// src/app/intelligence/iocs/page.tsx and threat-intel/page.tsx in the
// overlay). Combines what those two now-removed global pages did: browse/
// search/export the case's IOCs, import a custom list, and catch up
// enrichment — all through the same /api/ioc/* routes, just always passing
// this case's id.

type IocRecord = {
  id: string;
  value: string;
  type: string;
  reputation: number | null;
  createdAt: string;
  enrichments: { provider: string; status: string; enrichedAt: string | null }[];
  sources: string[];
};

type ThreatIntelStats = {
  totalIocs: number;
  enrichedIocs: number;
  pendingIocs: number;
  maliciousCount: number;
  suspiciousCount: number;
  cleanCount: number;
  providerStatus?: {
    name: string;
    label: string;
    configured: boolean;
    enabled: boolean;
    requiresKey: boolean;
    statusText: string;
    supportedTypes: string[];
  }[];
};

type ImportResult = {
  total: number; added: number; existing: number; skipped: number;
  skippedSamples: string[]; queuedEnrichment: number; truncated: boolean;
};

const TYPE_COLOR: Record<string, string> = {
  ip:     "text-orange-400",
  domain: "text-blue-400",
  url:    "text-purple-400",
  hash:   "text-teal-400",
  email:  "text-yellow-400",
};

const SOURCE_COLOR: Record<string, string> = {
  "Investigation":  "border-teal-800 bg-teal-900/20 text-teal-300",
  "Log Analysis":   "border-blue-800 bg-blue-900/20 text-blue-300",
  "PCAP Analysis":  "border-orange-800 bg-orange-900/20 text-orange-300",
  "RAM Analysis":   "border-purple-800 bg-purple-900/20 text-purple-300",
  "Manual Import":  "border-zinc-700 bg-zinc-800/40 text-zinc-300",
  "Threat Intel":   "border-yellow-800 bg-yellow-900/20 text-yellow-300",
};

function reputationColor(rep: number | null): string {
  if (rep === null) return "text-zinc-600";
  if (rep >= 70) return "text-red-400";
  if (rep >= 40) return "text-yellow-400";
  return "text-green-400";
}

export function CaseThreatIntelSection({ caseId }: { caseId: string }) {
  const [stats, setStats]       = useState<ThreatIntelStats | null>(null);
  const [iocs, setIocs]         = useState<IocRecord[]>([]);
  const [loading, setLoading]   = useState(true);
  const [q, setQ]               = useState("");
  const [page, setPage]         = useState(0);
  const PAGE = 25;

  const [showUpload, setShowUpload] = useState(false);
  const [file, setFile]             = useState<File | null>(null);
  const [queueEnrichment, setQueueEnrichment] = useState(false);
  const [uploading, setUploading]   = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [result, setResult]         = useState<ImportResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [enrichingAll, setEnrichingAll] = useState(false);
  const [enrichAllMsg, setEnrichAllMsg] = useState<string | null>(null);

  async function loadStats() {
    const res = await fetch(`/api/intelligence/stats?caseId=${caseId}`);
    if (res.ok) setStats(await res.json());
  }

  async function loadIocs(search = q, offset = page * PAGE) {
    setLoading(true);
    const params = new URLSearchParams({ caseId, limit: String(PAGE), offset: String(offset) });
    if (search) params.set("q", search);
    const res = await fetch(`/api/ioc/list?${params}`);
    if (res.ok) setIocs((await res.json()).iocs ?? []);
    setLoading(false);
  }

  useEffect(() => { loadStats(); loadIocs(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setPage(0);
    loadIocs(q, 0);
  }

  async function enrichAllUnenriched() {
    setEnrichingAll(true);
    setEnrichAllMsg(null);
    try {
      const res = await fetch("/api/ioc/enrich-all", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ caseId }),
      });
      const json = await res.json().catch(() => ({}));
      if (res.ok) {
        setEnrichAllMsg(
          `Checked ${json.feedChecked} URL${json.feedChecked !== 1 ? "s" : ""} against the local URLhaus feed (${json.feedMatches} match${json.feedMatches !== 1 ? "es" : ""}) ` +
          `and queued ${json.queued} never-enriched IOC${json.queued !== 1 ? "s" : ""} for live provider enrichment.` +
          (json.truncated ? " (Live-provider queue hit this run's cap — run again to continue.)" : "")
        );
        loadStats();
        loadIocs();
      } else {
        setEnrichAllMsg(json.message ?? "Enrich-all failed.");
      }
    } catch {
      setEnrichAllMsg("Enrich-all failed — check your connection.");
    } finally {
      setEnrichingAll(false);
    }
  }

  async function uploadIocList() {
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    setResult(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("caseId", caseId);
      formData.append("queueEnrichment", String(queueEnrichment));
      const res = await fetch("/api/ioc/import", { method: "POST", body: formData });
      const json = await res.json().catch(() => ({}));
      if (res.ok) {
        setResult(json);
        setFile(null);
        if (fileInputRef.current) fileInputRef.current.value = "";
        loadStats();
        loadIocs();
      } else {
        setUploadError(json.message ?? "Upload failed.");
      }
    } catch {
      setUploadError("Upload failed — check your connection and try again.");
    } finally {
      setUploading(false);
    }
  }

  const exportHref = `/api/ioc/export?caseId=${caseId}${q ? `&q=${encodeURIComponent(q)}` : ""}`;

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
          <Shield className="h-4 w-4 text-zinc-500" /> Threat Intel
        </h2>
        <div className="flex items-center gap-2">
          <button
            onClick={enrichAllUnenriched}
            disabled={enrichingAll}
            title="Enrich every IOC in this case that's never been checked against a provider"
            className="flex items-center gap-1.5 rounded-md border border-zinc-800 px-2.5 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 hover:border-zinc-600 disabled:opacity-50"
          >
            <Sparkles className="h-3.5 w-3.5" /> {enrichingAll ? "Enriching…" : "Enrich All"}
          </button>
          <button
            onClick={() => { setShowUpload((v) => !v); setUploadError(null); setResult(null); }}
            className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium ${
              showUpload ? "border-teal-700 bg-teal-900/30 text-teal-300" : "border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-600"
            }`}
          >
            <Upload className="h-3.5 w-3.5" /> Import
          </button>
          <a
            href={exportHref}
            className="flex items-center gap-1.5 rounded-md border border-zinc-800 px-2.5 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 hover:border-zinc-600"
          >
            <FileSpreadsheet className="h-3.5 w-3.5" /> Export
          </a>
          <button onClick={() => { loadStats(); loadIocs(); }} className="p-1.5 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-200">
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {enrichAllMsg && (
        <p className="mb-3 rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs text-zinc-400">{enrichAllMsg}</p>
      )}

      {showUpload && (
        <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 mb-4">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h3 className="text-sm font-semibold text-zinc-300">Import IOCs into this case</h3>
              <p className="text-xs text-zinc-500 mt-0.5">
                A plaintext .txt file, one indicator per line — IPv4 addresses, domains, URLs, or MD5/SHA1/SHA256 hashes.
                Lines starting with # and blank lines are ignored. Anything else is reported back as skipped.
              </p>
            </div>
            <button onClick={() => setShowUpload(false)} className="text-zinc-600 hover:text-zinc-300">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 rounded-md border border-dashed border-zinc-700 px-3 py-2 text-sm text-zinc-400 hover:border-teal-600 hover:text-teal-400 cursor-pointer">
              <FileText className="h-4 w-4" />
              {file ? file.name : "Choose .txt file…"}
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,text/plain"
                className="hidden"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </label>
            <label className="flex items-center gap-1.5 text-xs text-zinc-400">
              <input
                type="checkbox"
                checked={queueEnrichment}
                onChange={(e) => setQueueEnrichment(e.target.checked)}
                className="rounded border-zinc-700 bg-zinc-950"
              />
              Queue enrichment for newly added IOCs (uses provider quota — off by default)
            </label>
            <button
              onClick={uploadIocList}
              disabled={!file || uploading}
              className="rounded-md bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50"
            >
              {uploading ? "Uploading…" : "Upload"}
            </button>
          </div>
          {uploadError && (
            <p className="mt-3 text-xs rounded px-2 py-1.5 bg-red-900/30 text-red-400">{uploadError}</p>
          )}
          {result && (
            <div className="mt-3 rounded-md border border-zinc-800 bg-zinc-950 p-3 text-xs text-zinc-400 space-y-1">
              <p>
                <span className="text-teal-400 font-medium">{result.added}</span> added,{" "}
                <span className="text-zinc-300">{result.existing}</span> already known,{" "}
                <span className={result.skipped > 0 ? "text-orange-400" : "text-zinc-300"}>{result.skipped}</span> skipped (unrecognized format)
                {result.queuedEnrichment > 0 && <> · <span className="text-teal-400">{result.queuedEnrichment}</span> queued for enrichment</>}
              </p>
              {result.truncated && (
                <p className="text-orange-400">File exceeded 20,000 lines — only the first 20,000 were processed.</p>
              )}
              {result.skippedSamples.length > 0 && (
                <details className="mt-1">
                  <summary className="cursor-pointer text-zinc-500 hover:text-zinc-300">Show skipped line samples</summary>
                  <ul className="mt-1 space-y-0.5 font-mono">
                    {result.skippedSamples.map((s, i) => <li key={i} className="truncate">{s}</li>)}
                  </ul>
                </details>
              )}
            </div>
          )}
        </section>
      )}

      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
          {[
            { label: "Total", value: stats.totalIocs, icon: Globe, color: "text-zinc-300" },
            { label: "Enriched", value: stats.enrichedIocs, icon: CheckCircle, color: "text-teal-400" },
            { label: "Malicious", value: stats.maliciousCount, icon: XCircle, color: "text-red-400" },
            { label: "Suspicious", value: stats.suspiciousCount, icon: AlertTriangle, color: "text-orange-400" },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-900 p-3 text-center">
              <Icon className={`h-4 w-4 mx-auto mb-1.5 ${color}`} />
              <div className={`text-lg font-bold ${color}`}>{value}</div>
              <div className="text-[11px] text-zinc-500">{label}</div>
            </div>
          ))}
        </div>
      )}

      {stats?.providerStatus?.some((p) => p.requiresKey && !p.configured) && (
        <p className="mb-4 flex items-center gap-1.5 text-xs text-zinc-500">
          Some providers have no API key configured, so results may be incomplete.
          <Link href="/settings/threat-intel" className="inline-flex items-center gap-1 text-teal-400 hover:text-teal-300">
            <Settings className="h-3 w-3" /> Configure providers
          </Link>
        </p>
      )}

      <form onSubmit={handleSearch} className="mb-3">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search IOC value…"
          className="w-full max-w-md rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
        />
      </form>

      {loading ? (
        <div className="text-center py-10 text-zinc-600 text-sm">Loading IOCs…</div>
      ) : iocs.length === 0 ? (
        <div className="rounded-xl border border-dashed border-zinc-800 py-10 text-center text-zinc-600 text-sm">
          <Shield className="h-8 w-8 mx-auto mb-2 opacity-30" />
          No IOC records in this case yet.
        </div>
      ) : (
        <div className="rounded-xl border border-zinc-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900 text-left">
                <th className="px-3 py-2 font-medium text-zinc-400 text-xs">Value</th>
                <th className="px-3 py-2 font-medium text-zinc-400 text-xs">Type</th>
                <th className="px-3 py-2 font-medium text-zinc-400 text-xs">Source</th>
                <th className="px-3 py-2 font-medium text-zinc-400 text-xs" title="Threat-intel confidence that this indicator is malicious (0-100)">Score</th>
                <th className="px-3 py-2 font-medium text-zinc-400 text-xs">Enrichments</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {iocs.map((ioc) => {
                const enriched = ioc.enrichments.filter((e) => e.status === "ok");
                return (
                  <tr key={ioc.id} className="bg-zinc-950 hover:bg-zinc-900 transition-colors">
                    <td className="px-3 py-2 font-mono">
                      <Link href={`/intelligence/ioc/${encodeURIComponent(ioc.value)}?caseId=${caseId}`} className="text-teal-400 hover:text-teal-300 text-xs">
                        {ioc.value.length > 50 ? `${ioc.value.slice(0, 50)}…` : ioc.value}
                      </Link>
                    </td>
                    <td className={`px-3 py-2 text-xs font-medium ${TYPE_COLOR[ioc.type] ?? "text-zinc-400"}`}>{ioc.type}</td>
                    <td className="px-3 py-2">
                      {ioc.sources.length === 0 ? (
                        <span className="text-xs text-zinc-600">—</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {ioc.sources.map((s) => (
                            <span key={s} className={`inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium ${SOURCE_COLOR[s] ?? "border-zinc-700 bg-zinc-800 text-zinc-400"}`}>
                              {s}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className={`px-3 py-2 text-xs font-semibold ${reputationColor(ioc.reputation)}`}>{ioc.reputation !== null ? `${ioc.reputation}/100` : "—"}</td>
                    <td className="px-3 py-2 text-xs">
                      {enriched.length === 0 ? (
                        <span className="text-zinc-600">Not enriched</span>
                      ) : (
                        <span className="font-medium text-teal-400">{enriched.length} provider{enriched.length !== 1 ? "s" : ""}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="flex gap-2 mt-3 justify-center">
        <button onClick={() => { const p = Math.max(0, page - 1); setPage(p); loadIocs(q, p * PAGE); }} disabled={page === 0} className="rounded px-3 py-1 text-xs border border-zinc-800 text-zinc-500 disabled:opacity-30">
          Previous
        </button>
        <span className="px-3 py-1 text-xs text-zinc-500">Page {page + 1}</span>
        <button onClick={() => { const p = page + 1; setPage(p); loadIocs(q, p * PAGE); }} disabled={iocs.length < PAGE} className="rounded px-3 py-1 text-xs border border-zinc-800 text-zinc-500 disabled:opacity-30">
          Next
        </button>
      </div>
    </div>
  );
}
