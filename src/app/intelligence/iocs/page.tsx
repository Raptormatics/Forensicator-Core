"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { RefreshCw, Shield, FileSpreadsheet, X } from "lucide-react";
import { formatCaseNumber } from "@/lib/cases/case-number";

type IocRecord = {
  id: string;
  value: string;
  type: string;
  reputation: number | null;
  description: string | null;
  createdAt: string;
  enrichments: { provider: string; status: string; enrichedAt: string | null }[];
  sources: string[];
};

const TYPE_COLOR: Record<string, string> = {
  ip:     "text-orange-400",
  domain: "text-blue-400",
  url:    "text-purple-400",
  hash:   "text-teal-400",
  email:  "text-yellow-400",
};

const SOURCE_COLOR: Record<string, string> = {
  "Investigation":    "border-teal-800 bg-teal-900/20 text-teal-300",
  "Log Analysis":     "border-blue-800 bg-blue-900/20 text-blue-300",
  "PCAP Analysis":    "border-orange-800 bg-orange-900/20 text-orange-300",
  "RAM Analysis":     "border-purple-800 bg-purple-900/20 text-purple-300",
  "Threat Intel":     "border-yellow-800 bg-yellow-900/20 text-yellow-300",
};

function reputationColor(rep: number | null): string {
  if (rep === null) return "text-zinc-600";
  if (rep >= 70) return "text-red-400";
  if (rep >= 40) return "text-yellow-400";
  return "text-green-400";
}

type CaseOption = { id: string; caseSeq: number; title: string };

function IocIntelligence() {
  const searchParams = useSearchParams();
  const [iocs, setIocs]       = useState<IocRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ]             = useState("");
  const [caseId, setCaseId]   = useState("");
  const [minReputation, setMinReputation] = useState<number | null>(() => {
    const v = searchParams.get("minReputation");
    return v !== null ? Number(v) : null;
  });
  const [maxReputation, setMaxReputation] = useState<number | null>(() => {
    const v = searchParams.get("maxReputation");
    return v !== null ? Number(v) : null;
  });
  const [cases, setCases]     = useState<CaseOption[]>([]);
  const [page, setPage]       = useState(0);
  const PAGE = 50;

  async function load(search = q, offset = page * PAGE, cId = caseId, minRep = minReputation, maxRep = maxReputation) {
    setLoading(true);
    const params = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
    if (search) params.set("q", search);
    if (cId) params.set("caseId", cId);
    if (minRep !== null) params.set("minReputation", String(minRep));
    if (maxRep !== null) params.set("maxReputation", String(maxRep));
    const res = await fetch(`/api/ioc/list?${params}`);
    if (res.ok) setIocs((await res.json()).iocs ?? []);
    setLoading(false);
  }

  useEffect(() => {
    load();
    fetch("/api/cases")
      .then(r => r.ok ? r.json() : { cases: [] })
      .then(d => setCases((d.cases ?? []).map((c: { id: string; caseSeq: number; title: string }) => ({ id: c.id, caseSeq: c.caseSeq, title: c.title }))));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setPage(0);
    load(q, 0);
  }

  function clearReputationFilter() {
    setMinReputation(null);
    setMaxReputation(null);
    setPage(0);
    load(q, 0, caseId, null, null);
  }

  const exportParams = new URLSearchParams();
  if (q) exportParams.set("q", q);
  if (caseId) exportParams.set("caseId", caseId);
  if (minReputation !== null) exportParams.set("minReputation", String(minReputation));
  if (maxReputation !== null) exportParams.set("maxReputation", String(maxReputation));
  const exportHref = `/api/ioc/export${exportParams.toString() ? `?${exportParams}` : ""}`;

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">IOC Intelligence</h1>
          <p className="text-sm text-zinc-500 mt-0.5">All indicators extracted across investigations, log/PCAP/RAM analysis, and threat intel lookups</p>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={exportHref}
            className="flex items-center gap-1.5 rounded-md border border-zinc-800 px-3 py-2 text-xs text-zinc-400 hover:text-zinc-200 hover:border-zinc-600"
          >
            <FileSpreadsheet className="h-3.5 w-3.5" /> Export
          </a>
          <button onClick={() => load()} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-200">
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {(minReputation !== null || maxReputation !== null) && (
        <div className="mb-4 flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-red-500/40 bg-red-500/10 px-3 py-1 text-xs font-medium text-red-300">
            {minReputation !== null && maxReputation !== null
              ? `Threat score ${minReputation}–${maxReputation}`
              : minReputation !== null
              ? `Threat score ≥ ${minReputation}`
              : `Threat score ≤ ${maxReputation}`}
            <button onClick={clearReputationFilter} className="hover:text-red-100"><X className="h-3 w-3" /></button>
          </span>
        </div>
      )}

      <form onSubmit={handleSearch} className="mb-4 flex flex-wrap gap-2">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search IOC value…"
          className="w-full max-w-md rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
        />
        <select
          value={caseId}
          onChange={(e) => { setCaseId(e.target.value); setPage(0); load(q, 0, e.target.value); }}
          className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 outline-none focus:border-teal-500"
        >
          <option value="">All cases</option>
          {cases.map((c) => (
            <option key={c.id} value={c.id}>{formatCaseNumber(c.caseSeq)} — {c.title}</option>
          ))}
        </select>
      </form>

      {loading ? (
        <div className="text-center py-16 text-zinc-600">Loading IOCs…</div>
      ) : iocs.length === 0 ? (
        <div className="text-center py-16 text-zinc-600">
          <Shield className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p>No IOC records found.</p>
        </div>
      ) : (
        <div className="rounded-xl border border-zinc-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900 text-left">
                <th className="px-4 py-3 font-medium text-zinc-400">Value</th>
                <th className="px-4 py-3 font-medium text-zinc-400">Type</th>
                <th className="px-4 py-3 font-medium text-zinc-400">Source</th>
                <th className="px-4 py-3 font-medium text-zinc-400" title="Threat-intel confidence that this indicator is malicious (0-100)">Threat Score</th>
                <th className="px-4 py-3 font-medium text-zinc-400">Enrichments</th>
                <th className="px-4 py-3 font-medium text-zinc-400">First Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {iocs.map((ioc) => {
                const enriched = ioc.enrichments.filter((e) => e.status === "ok");
                return (
                  <tr key={ioc.id} className="bg-zinc-950 hover:bg-zinc-900 transition-colors">
                    <td className="px-4 py-3 font-mono">
                      <Link href={`/intelligence/ioc/${encodeURIComponent(ioc.value)}`} className="text-teal-400 hover:text-teal-300 text-xs">
                        {ioc.value.length > 60 ? `${ioc.value.slice(0, 60)}…` : ioc.value}
                      </Link>
                    </td>
                    <td className={`px-4 py-3 text-xs font-medium ${TYPE_COLOR[ioc.type] ?? "text-zinc-400"}`}>{ioc.type}</td>
                    <td className="px-4 py-3">
                      {ioc.sources.length === 0 ? (
                        <span className="text-xs text-zinc-600">—</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {ioc.sources.map((s) => (
                            <span key={s} className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${SOURCE_COLOR[s] ?? "border-zinc-700 bg-zinc-800 text-zinc-400"}`}>
                              {s}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className={`px-4 py-3 text-xs font-semibold ${reputationColor(ioc.reputation)}`}>{ioc.reputation !== null ? `${ioc.reputation}/100` : "—"}</td>
                    <td className="px-4 py-3">
                      {enriched.length === 0 ? (
                        <span className="text-xs text-zinc-600">Not enriched</span>
                      ) : (
                        <span className="text-xs font-medium text-teal-400">
                          enriched ({enriched.length} provider{enriched.length !== 1 ? "s" : ""})
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-600">{new Date(ioc.createdAt).toLocaleDateString()}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      <div className="flex gap-2 mt-4 justify-center">
        <button onClick={() => { setPage((p) => Math.max(0, p - 1)); load(q, Math.max(0, (page - 1) * PAGE)); }} disabled={page === 0} className="rounded px-3 py-1 text-sm border border-zinc-800 text-zinc-500 disabled:opacity-30">
          Previous
        </button>
        <span className="px-3 py-1 text-sm text-zinc-500">Page {page + 1}</span>
        <button onClick={() => { setPage((p) => p + 1); load(q, (page + 1) * PAGE); }} disabled={iocs.length < PAGE} className="rounded px-3 py-1 text-sm border border-zinc-800 text-zinc-500 disabled:opacity-30">
          Next
        </button>
      </div>
    </div>
  );
}

export default function IocIntelligencePage() {
  return (
    <Suspense>
      <IocIntelligence />
    </Suspense>
  );
}
