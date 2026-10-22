"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, CheckCircle2, Clock, FileSpreadsheet, Globe, Loader2,
  Network, RefreshCw, Shield, Zap,
} from "lucide-react";
import { UploadEnrichButton } from "@/components/intelligence/upload-enrich-button";
import { CaseBadge } from "@/components/cases/case-badge";
import { ArchiveButton, ArchivedPill } from "@/components/cases/archive-button";

// ── Types ──────────────────────────────────────────────────────────────────

type Upload = {
  case: { id: string; caseSeq: number; title: string; status: string; archivedAt: string | null } | null;
  archivedAt: string | null;
  id: string; filename: string; status: string; errorMessage: string | null;
  packetCount: number; byteCount: string; linkType: string | null;
  captureStart: string | null; captureEnd: string | null;
  conversationCount: number; dnsQueryCount: number; findingCount: number; iocCount: number;
  hostname: string | null; assetName: string | null; ipAddress: string | null;
  createdAt: string;
  organization: { name: string } | null;
};

type Conversation = {
  id: string; protocol: string;
  addrA: string; portA: number | null; addrB: string; portB: number | null;
  packetsAtoB: number; packetsBtoA: number; bytesAtoB: string; bytesBtoA: string;
  firstSeen: string | null; lastSeen: string | null; tlsSni: string | null;
};

type DnsQuery = {
  id: string; queryName: string; queryType: string | null;
  responseIps: string[]; count: number;
  firstSeen: string | null; lastSeen: string | null;
};

type Finding = {
  id: string; title: string; description: string | null; severity: string;
  matchCount: number; firstSeen: string | null; lastSeen: string | null;
  matchedField: string | null; matchedValue: string | null;
  rule: { id: string; name: string; tags: string[] } | null;
};

type Ioc = { id: string; type: string; value: string; count: number };

type Tab = "overview" | "conversations" | "dns" | "findings" | "iocs";

// ── Helpers ────────────────────────────────────────────────────────────────

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-900/40 text-red-400 border-red-900",
  high:     "bg-orange-900/40 text-orange-400 border-orange-900",
  medium:   "bg-yellow-900/40 text-yellow-400 border-yellow-900",
  low:      "bg-blue-900/40 text-blue-400 border-blue-900",
  info:     "bg-zinc-800 text-zinc-400 border-zinc-700",
};

const IN_FLIGHT_STATUSES = new Set(["queued", "processing"]);

function formatBytes(bytes: string): string {
  const n = Number(bytes);
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

// ── Main Component ──────────────────────────────────────────────────────────

export default function PcapUploadDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [upload, setUpload]               = useState<Upload | null>(null);
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [dnsQueries, setDnsQueries]       = useState<DnsQuery[]>([]);
  const [findings, setFindings]           = useState<Finding[]>([]);
  const [iocs, setIocs]                   = useState<Ioc[]>([]);
  const [loading, setLoading]             = useState(true);
  const [tab, setTab]                     = useState<Tab>("overview");
  const [iocFilter, setIocFilter]         = useState<string>("all");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res  = await fetch(`/api/pcap-analysis/uploads/${id}`);
      const data = await res.json();
      setUpload(data.upload ?? null);
      setConversations(data.conversations?.data ?? []);
      setDnsQueries(data.dnsQueries ?? []);
      setFindings(data.findings ?? []);
      setIocs(data.iocs ?? []);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  // Poll while the capture is still being parsed.
  useEffect(() => {
    if (!upload || !IN_FLIGHT_STATUSES.has(upload.status)) return;
    const interval = setInterval(load, 5_000);
    return () => clearInterval(interval);
  }, [upload, load]);

  const iocTypes = ["all", ...Array.from(new Set(iocs.map((i) => i.type)))];
  const filteredIocs = iocFilter === "all" ? iocs : iocs.filter((i) => i.type === iocFilter);

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount     = findings.filter((f) => f.severity === "high").length;

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
            <Link href="/pcap-analysis" className="flex items-center gap-1.5 hover:text-zinc-300">
              <ArrowLeft className="h-3.5 w-3.5" /> PCAP Analysis
            </Link>
            <span>/</span>
            <span className="text-zinc-300 truncate max-w-xs">{upload.filename}</span>
          </div>

          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <div className="flex items-center gap-2 text-sm text-teal-200 mb-1">
                <Network className="h-4 w-4" />
                PCAP Analysis
              </div>
              <h1 className="text-2xl font-semibold text-zinc-50 break-all">{upload.filename}</h1>
              {upload.case && <div className="mt-1 text-sm"><CaseBadge kase={upload.case} showTitle /></div>}
              {/* Only an upload with no case is archived on its own — one in a case goes with its case. */}
              {!upload.case && (
                <div className="mt-2 flex items-center gap-2">
                  {upload.archivedAt && <ArchivedPill />}
                  <ArchiveButton type="pcap" id={upload.id} action={upload.archivedAt ? "restore" : "archive"} onDone={() => load()} />
                </div>
              )}
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
                {upload.linkType && <><span>·</span><span>{upload.linkType}</span></>}
                {upload.hostname && <><span>·</span><span>{upload.hostname}</span></>}
                {upload.organization && <><span>·</span><span>{upload.organization.name}</span></>}
                <span>·</span>
                <span>{new Date(upload.createdAt).toLocaleString()}</span>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <UploadEnrichButton endpoint={`/api/pcap-analysis/uploads/${id}/enrich`} />
              <a
                href={`/api/pcap-analysis/uploads/${id}/export`}
                className="flex items-center gap-1.5 rounded border border-zinc-800 px-3 py-2 text-xs text-zinc-400 hover:text-zinc-200 hover:border-zinc-600"
              >
                <FileSpreadsheet className="h-3.5 w-3.5" /> Export
              </a>
              <button onClick={() => load()} className="p-2 rounded border border-zinc-800 text-zinc-500 hover:text-zinc-200">
                <RefreshCw className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Summary bar */}
          <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: "Packets",       value: upload.packetCount.toLocaleString(),          color: "text-zinc-100" },
              { label: "Data Volume",   value: formatBytes(upload.byteCount),                 color: "text-zinc-100" },
              { label: "Findings",      value: upload.findingCount, color: upload.findingCount > 0 ? "text-orange-400" : "text-zinc-100" },
              { label: "Critical / High", value: `${criticalCount} / ${highCount}`, color: (criticalCount + highCount) > 0 ? "text-red-400" : "text-zinc-100" },
            ].map(({ label, value, color }) => (
              <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
                <p className="text-xs text-zinc-500">{label}</p>
                <p className={`mt-1 text-xl font-semibold ${color}`}>{value}</p>
              </div>
            ))}
          </div>

          {IN_FLIGHT_STATUSES.has(upload.status) && (
            <div className="mt-4 flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/60 px-4 py-3 text-sm text-zinc-400">
              <Loader2 className="h-4 w-4 animate-spin text-yellow-400" />
              {upload.status === "queued" ? "Waiting for a worker to pick up this capture…" : "Parsing packets and extracting conversations, DNS activity, and IOCs…"}
            </div>
          )}

          {upload.errorMessage && (
            <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-900/40 bg-red-950/20 px-4 py-3 text-sm text-red-400">
              <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
              {upload.errorMessage}
            </div>
          )}

          {/* Tabs */}
          <div className="mt-6 flex gap-1 border-b border-zinc-800 overflow-x-auto">
            {([
              { id: "overview",      label: "Overview",      count: null },
              { id: "conversations", label: "Conversations", count: upload.conversationCount },
              { id: "dns",           label: "DNS",            count: upload.dnsQueryCount },
              { id: "findings",      label: "Findings",       count: findings.length },
              { id: "iocs",          label: "IOCs",           count: iocs.length },
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
              <h3 className="text-sm font-semibold text-zinc-200 mb-3">Capture Details</h3>
              <dl className="space-y-2 text-xs">
                {[
                  ["Filename", upload.filename],
                  ["Link type", upload.linkType ?? "—"],
                  ["Capture start", upload.captureStart ? new Date(upload.captureStart).toLocaleString() : "—"],
                  ["Capture end", upload.captureEnd ? new Date(upload.captureEnd).toLocaleString() : "—"],
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
              <h3 className="text-sm font-semibold text-zinc-200 mb-3">Extraction Summary</h3>
              <dl className="space-y-2 text-xs">
                {[
                  ["Conversations", upload.conversationCount.toLocaleString()],
                  ["DNS queries", upload.dnsQueryCount.toLocaleString()],
                  ["IOCs", upload.iocCount.toLocaleString()],
                  ["Findings", upload.findingCount.toLocaleString()],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-4">
                    <dt className="text-zinc-500">{k}</dt>
                    <dd className="text-zinc-300">{v}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>
        )}

        {/* ── CONVERSATIONS TAB ── */}
        {tab === "conversations" && (
          conversations.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <Network className="h-10 w-10 text-zinc-600 mb-3" />
              <p className="text-sm text-zinc-400 font-medium">No conversations extracted</p>
            </div>
          ) : (
            <div className="rounded-xl border border-zinc-800 overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-900">
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Protocol</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Endpoint A</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Endpoint B</th>
                    <th className="px-3 py-2.5 text-right text-zinc-500 font-medium">Packets</th>
                    <th className="px-3 py-2.5 text-right text-zinc-500 font-medium">Bytes</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">TLS SNI</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium whitespace-nowrap">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/50 bg-zinc-950">
                  {conversations.map((c) => (
                    <tr key={c.id} className="hover:bg-zinc-900/60 transition-colors">
                      <td className="px-3 py-2 font-mono text-sky-400 uppercase">{c.protocol}</td>
                      <td className="px-3 py-2 font-mono text-blue-400">{c.addrA}{c.portA ? `:${c.portA}` : ""}</td>
                      <td className="px-3 py-2 font-mono text-blue-400">{c.addrB}{c.portB ? `:${c.portB}` : ""}</td>
                      <td className="px-3 py-2 text-right text-zinc-300">{(c.packetsAtoB + c.packetsBtoA).toLocaleString()}</td>
                      <td className="px-3 py-2 text-right text-zinc-300">{formatBytes(String(BigInt(c.bytesAtoB) + BigInt(c.bytesBtoA)))}</td>
                      <td className="px-3 py-2 text-zinc-400 truncate max-w-[160px]" title={c.tlsSni ?? ""}>{c.tlsSni ?? "—"}</td>
                      <td className="px-3 py-2 text-zinc-500 whitespace-nowrap">{c.lastSeen ? new Date(c.lastSeen).toLocaleString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        )}

        {/* ── DNS TAB ── */}
        {tab === "dns" && (
          dnsQueries.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <Globe className="h-10 w-10 text-zinc-600 mb-3" />
              <p className="text-sm text-zinc-400 font-medium">No DNS queries extracted</p>
            </div>
          ) : (
            <div className="rounded-xl border border-zinc-800 overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-900">
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Query</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Type</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Response IPs</th>
                    <th className="px-3 py-2.5 text-right text-zinc-500 font-medium">Count</th>
                    <th className="px-3 py-2.5 text-left text-zinc-500 font-medium whitespace-nowrap">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/50 bg-zinc-950">
                  {dnsQueries.map((d) => (
                    <tr key={d.id} className="hover:bg-zinc-900/60 transition-colors">
                      <td className="px-3 py-2 font-mono text-green-400 truncate max-w-[220px]" title={d.queryName}>{d.queryName}</td>
                      <td className="px-3 py-2 text-zinc-400">{d.queryType ?? "—"}</td>
                      <td className="px-3 py-2 font-mono text-blue-400 truncate max-w-[220px]" title={d.responseIps.join(", ")}>{d.responseIps.join(", ") || "—"}</td>
                      <td className="px-3 py-2 text-right text-zinc-300">{d.count.toLocaleString()}</td>
                      <td className="px-3 py-2 text-zinc-500 whitespace-nowrap">{d.lastSeen ? new Date(d.lastSeen).toLocaleString() : "—"}</td>
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
              <p className="text-xs text-zinc-600 mt-1">No heuristics or rules matched traffic in this capture</p>
              <Link href="/pcap-analysis/rules" className="mt-4 text-sm text-teal-400 hover:text-teal-300">
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
                          <Zap className="h-3 w-3" /> {f.matchCount.toLocaleString()} match{f.matchCount !== 1 ? "es" : ""}
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
                    className="flex items-center gap-2.5 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2.5 text-blue-300 transition hover:brightness-125"
                  >
                    <Globe className="h-3.5 w-3.5" />
                    <span className="font-mono text-xs truncate flex-1">{ioc.value}</span>
                    <span className="shrink-0 text-xs opacity-60">×{ioc.count}</span>
                  </Link>
                ))}
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}
