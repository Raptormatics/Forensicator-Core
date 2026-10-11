"use client";

import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import { RefreshCw, Globe, CheckCircle, XCircle, AlertTriangle, Upload, FileText, X, ShieldCheck, Sparkles, Settings } from "lucide-react";
import { PROVIDER_LABEL } from "@/lib/intelligence/verdict";

type ThreatIntelStats = {
  totalIocs: number;
  enrichedIocs: number;
  pendingIocs: number;
  maliciousCount: number;
  suspiciousCount: number;
  cleanCount: number;
  byProvider: Record<string, { total: number; malicious: number; suspicious: number }>;
  recentEnrichments: {
    iocValue: string;
    iocType: string;
    provider: string;
    status: string;
    verdict: string;
    score: number | null;
    createdAt: string;
  }[];
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

const LOG_STATUS_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: "ok", label: "Enriched" },
  { value: "error", label: "Error" },
  { value: "not_found", label: "Not found" },
  { value: "pending", label: "Pending" },
];

function logStatusColor(status: string): string {
  if (status === "ok") return "text-green-400";
  if (status === "error") return "text-red-400";
  if (status === "not_found") return "text-zinc-500";
  return "text-amber-400"; // pending / anything else
}

function formatLogTimestamp(value: string): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return new Intl.DateTimeFormat("en", { dateStyle: "short", timeStyle: "medium" }).format(d);
}

export default function ThreatIntelPage() {
  const [stats, setStats]     = useState<ThreatIntelStats | null>(null);
  const [loading, setLoading] = useState(true);

  const [showUpload, setShowUpload] = useState(false);
  const [file, setFile]             = useState<File | null>(null);
  const [queueEnrichment, setQueueEnrichment] = useState(false);
  const [uploading, setUploading]   = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [result, setResult]         = useState<ImportResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [syncing, setSyncing]     = useState(false);
  const [syncMsg, setSyncMsg]     = useState<string | null>(null);
  const [enrichingAll, setEnrichingAll] = useState(false);
  const [enrichAllMsg, setEnrichAllMsg] = useState<string | null>(null);

  const [logStatus, setLogStatus] = useState("");
  const [logProvider, setLogProvider] = useState("");

  async function load(status = logStatus, provider = logProvider) {
    setLoading(true);
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (provider) params.set("provider", provider);
    const res = await fetch(`/api/intelligence/stats${params.toString() ? `?${params}` : ""}`);
    if (res.ok) setStats(await res.json());
    setLoading(false);
  }

  async function syncUrlhausFeed() {
    setSyncing(true);
    setSyncMsg(null);
    try {
      const res = await fetch("/api/intelligence/urlhaus-sync", { method: "POST" });
      const json = await res.json().catch(() => ({}));
      setSyncMsg(res.ok ? `Synced — ${json.added} new indicator${json.added !== 1 ? "s" : ""} of ${json.total} total in the feed.` : (json.message ?? "Sync failed."));
    } catch {
      setSyncMsg("Sync failed — check your connection.");
    } finally {
      setSyncing(false);
    }
  }

  async function enrichAllUnenriched() {
    setEnrichingAll(true);
    setEnrichAllMsg(null);
    try {
      const res = await fetch("/api/ioc/enrich-all", {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      });
      const json = await res.json().catch(() => ({}));
      if (res.ok) {
        setEnrichAllMsg(
          `Checked ${json.feedChecked} URL${json.feedChecked !== 1 ? "s" : ""} against the local URLhaus feed (${json.feedMatches} match${json.feedMatches !== 1 ? "es" : ""}) ` +
          `and queued ${json.queued} never-enriched IOC${json.queued !== 1 ? "s" : ""} for live provider enrichment.` +
          (json.truncated ? " (Live-provider queue hit this run's cap — run again to continue.)" : "")
        );
        load();
      } else {
        setEnrichAllMsg(json.message ?? "Enrich-all failed.");
      }
    } catch {
      setEnrichAllMsg("Enrich-all failed — check your connection.");
    } finally {
      setEnrichingAll(false);
    }
  }

  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function changeLogStatus(v: string) {
    setLogStatus(v);
    load(v, logProvider);
  }

  function changeLogProvider(v: string) {
    setLogProvider(v);
    load(logStatus, v);
  }

  async function uploadIocList() {
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    setResult(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("queueEnrichment", String(queueEnrichment));
      const res = await fetch("/api/ioc/import", { method: "POST", body: formData });
      const json = await res.json().catch(() => ({}));
      if (res.ok) {
        setResult(json);
        setFile(null);
        if (fileInputRef.current) fileInputRef.current.value = "";
        load();
      } else {
        setUploadError(json.message ?? "Upload failed.");
      }
    } catch {
      setUploadError("Upload failed — check your connection and try again.");
    } finally {
      setUploading(false);
    }
  }

  if (loading && !stats) return <div className="p-8 text-zinc-500">Loading…</div>;
  if (!stats)  return <div className="p-8 text-red-400">Failed to load threat intelligence stats.</div>;

  const enrichmentPct = stats.totalIocs > 0 ? Math.round((stats.enrichedIocs / stats.totalIocs) * 100) : 0;
  const providerNames = Object.keys(stats.byProvider);

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">Threat Intelligence</h1>
          <p className="text-sm text-zinc-500 mt-0.5">Enrichment coverage and provider status</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={enrichAllUnenriched}
            disabled={enrichingAll}
            title="Enrich every IocRecord that's never been checked against a provider — catches uploads from before auto-enrichment existed"
            className="flex items-center gap-1.5 rounded-md border border-zinc-800 px-3 py-2 text-sm text-zinc-400 hover:text-zinc-200 hover:border-zinc-600 disabled:opacity-50"
          >
            <Sparkles className="h-4 w-4" /> {enrichingAll ? "Enriching…" : "Enrich All Unenriched"}
          </button>
          <button
            onClick={syncUrlhausFeed}
            disabled={syncing}
            title="Refresh the local URLhaus feed cache used for free, automatic URL matching"
            className="flex items-center gap-1.5 rounded-md border border-zinc-800 px-3 py-2 text-sm text-zinc-400 hover:text-zinc-200 hover:border-zinc-600 disabled:opacity-50"
          >
            <ShieldCheck className="h-4 w-4" /> {syncing ? "Syncing…" : "Sync URLhaus Feed"}
          </button>
          <button
            onClick={() => { setShowUpload((v) => !v); setUploadError(null); setResult(null); }}
            className={`flex items-center gap-1.5 rounded-md border px-3 py-2 text-sm font-medium ${
              showUpload ? "border-teal-700 bg-teal-900/30 text-teal-300" : "border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-600"
            }`}
          >
            <Upload className="h-4 w-4" /> Upload IOC List
          </button>
          <button onClick={() => load()} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-200">
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {(syncMsg || enrichAllMsg) && (
        <div className="mb-6 space-y-2">
          {syncMsg && <p className="rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs text-zinc-400">{syncMsg}</p>}
          {enrichAllMsg && <p className="rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs text-zinc-400">{enrichAllMsg}</p>}
        </div>
      )}

      {/* Custom IOC list upload */}
      {showUpload && (
        <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 mb-6">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-zinc-300">Upload a custom IOC list</h2>
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

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: "Total IOCs", value: stats.totalIocs, icon: Globe, color: "text-zinc-300", sub: "every tracked indicator", href: null },
          { label: "Enriched", value: `${stats.enrichedIocs} (${enrichmentPct}%)`, icon: CheckCircle, color: "text-teal-400", sub: "distinct IOCs with ≥1 provider result", href: null },
          { label: "Malicious", value: stats.maliciousCount, icon: XCircle, color: "text-red-400", sub: "aggregate threat score ≥ 70", href: "/intelligence/iocs?minReputation=70" },
          { label: "Suspicious", value: stats.suspiciousCount, icon: AlertTriangle, color: "text-orange-400", sub: "aggregate threat score 40–69", href: "/intelligence/iocs?minReputation=40&maxReputation=69" },
        ].map(({ label, value, icon: Icon, color, sub, href }) => {
          const content = (
            <>
              <Icon className={`h-5 w-5 mx-auto mb-2 ${color}`} />
              <div className={`text-xl font-bold ${color}`}>{value}</div>
              <div className="text-xs text-zinc-500 mt-1">{label}</div>
              <div className="text-[10px] text-zinc-600 mt-1" title={sub}>{sub}</div>
            </>
          );
          return href ? (
            <Link
              key={label}
              href={href}
              className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 text-center hover:border-zinc-600 hover:bg-zinc-900/70 transition-colors"
            >
              {content}
            </Link>
          ) : (
            <div key={label} className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 text-center">
              {content}
            </div>
          );
        })}
      </div>

      {/* Provider status */}
      {stats.providerStatus && (
        <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 mb-4">
          <h2 className="text-sm font-semibold text-zinc-300 mb-3">Provider Status</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {stats.providerStatus.map((p) => {
              const needsKey = p.requiresKey && !p.configured;
              return (
                <div key={p.name} className="flex items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-950 p-3">
                  <div className={`mt-0.5 h-2 w-2 rounded-full shrink-0 ${p.configured ? "bg-teal-400" : "bg-zinc-600"}`} />
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium text-zinc-300 truncate">{p.label}</div>
                    <div className="text-xs text-zinc-600 mt-0.5">{p.statusText}</div>
                    <div className="text-xs text-zinc-700 mt-0.5">{p.supportedTypes.join(", ")}</div>
                    {needsKey && (
                      <Link
                        href={`/settings/threat-intel?provider=${p.name}`}
                        className="mt-2 inline-flex items-center gap-1 rounded border border-zinc-700 px-2 py-1 text-[11px] font-medium text-teal-400 hover:border-teal-600 hover:bg-teal-900/20"
                      >
                        <Settings className="h-3 w-3" /> Configure
                      </Link>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* Provider breakdown */}
      <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 mb-6">
        <h2 className="text-sm font-semibold text-zinc-300 mb-3">Provider Breakdown</h2>
        {providerNames.length === 0 ? (
          <p className="text-sm text-zinc-600">No enrichments yet. Trigger enrichment from an IOC record.</p>
        ) : (
          <div className="space-y-2">
            {providerNames
              .filter((p) => p !== "urlhaus_feed")
              .map((provider) => (
                <div key={provider}>
                  <ProviderBreakdownRow label={PROVIDER_LABEL[provider] ?? provider} data={stats.byProvider[provider]} />
                  {provider === "urlhaus" && stats.byProvider["urlhaus_feed"] && (
                    <ProviderBreakdownRow
                      indent
                      label="↳ Local feed cache"
                      data={stats.byProvider["urlhaus_feed"]}
                    />
                  )}
                </div>
              ))}
            {/* Local feed matches exist but no live urlhaus provider hits yet — show it standalone. */}
            {!providerNames.includes("urlhaus") && stats.byProvider["urlhaus_feed"] && (
              <ProviderBreakdownRow label={PROVIDER_LABEL["urlhaus_feed"]} data={stats.byProvider["urlhaus_feed"]} />
            )}
          </div>
        )}
      </section>

      {/* Recent enrichments */}
      <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <h2 className="text-sm font-semibold text-zinc-300">Recent Enrichments</h2>
          <div className="flex items-center gap-2">
            <select
              value={logStatus}
              onChange={(e) => changeLogStatus(e.target.value)}
              className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-300 outline-none focus:border-teal-500"
            >
              {LOG_STATUS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
            <select
              value={logProvider}
              onChange={(e) => changeLogProvider(e.target.value)}
              className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-300 outline-none focus:border-teal-500"
            >
              <option value="">All providers</option>
              {providerNames.map((p) => (
                <option key={p} value={p}>{PROVIDER_LABEL[p] ?? p}</option>
              ))}
            </select>
          </div>
        </div>
        {stats.recentEnrichments.length === 0 ? (
          <p className="text-sm text-zinc-600">No enrichments match this filter.</p>
        ) : (
          <div className="space-y-2">
            {stats.recentEnrichments.map((e, i) => (
              <div key={i} className="flex items-center gap-3 text-xs">
                <span className="font-mono text-teal-400 truncate max-w-xs">{e.iocValue}</span>
                <span className="text-zinc-600">{e.iocType}</span>
                <span className="text-zinc-500">{PROVIDER_LABEL[e.provider] ?? e.provider}</span>
                <span className={`font-medium ${logStatusColor(e.status)}`}>{e.verdict}</span>
                {e.score !== null && <span className="text-zinc-600">score: {e.score}</span>}
                <span className="ml-auto text-zinc-700 font-mono">{formatLogTimestamp(e.createdAt)}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function ProviderBreakdownRow({ label, data, indent }: { label: string; data: { total: number; malicious: number; suspicious: number }; indent?: boolean }) {
  return (
    <div className={`flex items-center gap-4 text-sm ${indent ? "pl-6 opacity-80" : ""}`}>
      <span className="w-36 text-zinc-400 shrink-0">{label}</span>
      <span className="text-zinc-500">{data.total} hits</span>
      <span className="text-red-400">{data.malicious} malicious</span>
      <span className="text-orange-400">{data.suspicious} suspicious</span>
    </div>
  );
}
