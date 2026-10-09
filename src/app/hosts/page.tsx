"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import {
  Monitor, RefreshCw, AlertTriangle, ArrowUp, ArrowDown, ArrowUpDown,
  AppWindow, Apple, Terminal, ShieldOff, ShieldCheck, ShieldQuestion,
  Download, X, FolderPlus, Search, User as UserIcon, Network,
} from "lucide-react";
import { formatCaseNumber } from "@/lib/cases/case-number";
import { RISK_META, ISOLATION_LABEL, ISOLATION_CLASS, type RiskTier, type IsolationStatus } from "@/lib/hosts/risk-ui";

type HostSummary = {
  hostname: string;
  osInfo: unknown | null;
  riskScore: number;
  riskTier: RiskTier;
  investigationCount: number;
  findingCount: number;
  criticalCount: number;
  highCount: number;
  iocMatchCount: number;
  usbActivity: number;
  persistenceEvents: number;
  primaryUser: string | null;
  lastKnownIp: string | null;
  isolationStatus: IsolationStatus;
  isolationNote: string | null;
  isolationUpdatedAt: string | null;
  isolationUpdatedBy: { email: string; name: string | null } | null;
  lastSeen: string;
  firstSeen: string;
};

type CaseRef = { id: string; title: string; caseSeq: number; status: string; severity: string };
type TopIoc = { value: string; type: string; reputation: number | null; threatType: string | null; malwareFamily: string | null };
type CaseOption = { id: string; caseSeq: number; title: string };

const ISOLATION_ICON: Record<IsolationStatus, typeof ShieldCheck> = {
  active: ShieldQuestion,
  quarantined: ShieldOff,
  offline: ShieldCheck,
};
const ISOLATION_META: Record<IsolationStatus, { label: string; cls: string; icon: typeof ShieldCheck }> = {
  active:      { label: ISOLATION_LABEL.active,      cls: ISOLATION_CLASS.active,      icon: ISOLATION_ICON.active },
  quarantined: { label: ISOLATION_LABEL.quarantined, cls: ISOLATION_CLASS.quarantined, icon: ISOLATION_ICON.quarantined },
  offline:     { label: ISOLATION_LABEL.offline,     cls: ISOLATION_CLASS.offline,     icon: ISOLATION_ICON.offline },
};

function osMeta(osInfo: unknown): { Icon: typeof Monitor; label: string } {
  const platform = typeof osInfo === "object" && osInfo !== null
    ? String((osInfo as Record<string, unknown>).platform ?? "").toLowerCase()
    : "";
  if (platform.includes("win")) return { Icon: AppWindow, label: "Windows" };
  if (platform.includes("mac") || platform.includes("darwin")) return { Icon: Apple, label: "macOS" };
  if (platform.includes("linux") || platform.includes("nix")) return { Icon: Terminal, label: "Linux" };
  return { Icon: Monitor, label: platform || "Unknown" };
}

function muted(value: number, cls: string): string {
  return value === 0 ? "text-zinc-700" : cls;
}

type SortKey = "hostname" | "riskScore" | "investigationCount" | "findingCount" | "iocMatchCount" | "usbActivity" | "persistenceEvents" | "lastSeen";

const COLUMNS: { key: SortKey; label: string; align: "left" | "right"; title?: string }[] = [
  { key: "hostname",           label: "Hostname",        align: "left" },
  { key: "riskScore",          label: "Risk",            align: "right" },
  { key: "investigationCount", label: "Investigations",  align: "right" },
  { key: "findingCount",       label: "Findings",        align: "right" },
  { key: "iocMatchCount",      label: "IOC Hits",        align: "right" },
  { key: "usbActivity",        label: "USB",             align: "right" },
  { key: "persistenceEvents",  label: "Persistence",     align: "right", title: "Persistence mechanisms detected — autorun keys, scheduled tasks, services, startup items" },
  { key: "lastSeen",           label: "Last Seen",       align: "right" },
];

export default function HostsPage() {
  const [hosts, setHosts]     = useState<HostSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ]             = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("riskScore");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [toast, setToast]     = useState<string | null>(null);

  const [peekHostname, setPeekHostname] = useState<string | null>(null);
  const [peekLoading, setPeekLoading]   = useState(false);
  const [peekHost, setPeekHost]         = useState<HostSummary | null>(null);
  const [peekCases, setPeekCases]       = useState<CaseRef[]>([]);
  const [peekIocs, setPeekIocs]         = useState<TopIoc[]>([]);
  const [isolationNoteDraft, setIsolationNoteDraft] = useState("");
  const [savingIsolation, setSavingIsolation]       = useState(false);

  const [caseModalOpen, setCaseModalOpen] = useState(false);
  const [caseSearch, setCaseSearch]       = useState("");
  const [caseOptions, setCaseOptions]     = useState<CaseOption[]>([]);
  const [addingToCase, setAddingToCase]   = useState(false);

  const [isolateConfirmOpen, setIsolateConfirmOpen] = useState(false);
  const [isolating, setIsolating]                   = useState(false);

  function showToast(msg: string) {
    setToast(msg);
    setTimeout(() => setToast((cur) => (cur === msg ? null : cur)), 3000);
  }

  async function load() {
    setLoading(true);
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    const res = await fetch(`/api/hosts?${params}`);
    const data = await res.json();
    setHosts(data.hosts ?? []);
    setLoading(false);
  }

  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    load();
  }

  function toggleSort(key: SortKey) {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir("desc"); }
  }

  const sorted = useMemo(() => {
    const arr = [...hosts];
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "hostname") cmp = a.hostname.localeCompare(b.hostname);
      else if (sortKey === "lastSeen") cmp = a.lastSeen.localeCompare(b.lastSeen);
      else cmp = (a[sortKey] as number) - (b[sortKey] as number);
      return sortDir === "asc" ? cmp : -cmp;
    });
    return arr;
  }, [hosts, sortKey, sortDir]);

  function toggleSelect(hostname: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(hostname)) next.delete(hostname); else next.add(hostname);
      return next;
    });
  }

  function toggleSelectAll() {
    setSelected((prev) => (prev.size === sorted.length ? new Set() : new Set(sorted.map((h) => h.hostname))));
  }

  function exportCsv() {
    const rows = sorted.filter((h) => selected.has(h.hostname));
    const headers = ["hostname", "os", "risk_tier", "risk_score", "investigations", "findings", "critical_findings", "ioc_hits", "usb_events", "persistence_events", "primary_user", "last_known_ip", "isolation_status", "last_seen"];
    const esc = (v: string | number) => {
      const s = String(v);
      return s.includes(",") || s.includes("\n") || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const lines = [headers.join(",")];
    for (const h of rows) {
      lines.push([
        h.hostname, osMeta(h.osInfo).label, h.riskTier, h.riskScore, h.investigationCount, h.findingCount,
        h.criticalCount, h.iocMatchCount, h.usbActivity, h.persistenceEvents, h.primaryUser ?? "", h.lastKnownIp ?? "",
        h.isolationStatus, h.lastSeen,
      ].map(esc).join(","));
    }
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hosts-export-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`Exported ${rows.length} host${rows.length !== 1 ? "s" : ""} to CSV.`);
  }

  useEffect(() => {
    if (!caseModalOpen) return;
    fetch(`/api/cases${caseSearch.trim() ? `?q=${encodeURIComponent(caseSearch.trim())}` : ""}`)
      .then((r) => (r.ok ? r.json() : { cases: [] }))
      .then((d) => setCaseOptions(d.cases ?? []));
  }, [caseModalOpen, caseSearch]);

  async function addSelectedToCase(c: CaseOption) {
    setAddingToCase(true);
    const rows = sorted.filter((h) => selected.has(h.hostname));
    try {
      await Promise.all(rows.map((h) => {
        const content =
          `Host flagged for review: ${h.hostname}\n` +
          `- Risk: ${RISK_META[h.riskTier].label} (${h.riskScore})\n` +
          `- Findings: ${h.findingCount} (${h.criticalCount} critical)\n` +
          `- IOC hits: ${h.iocMatchCount}\n` +
          (h.primaryUser ? `- Primary user: ${h.primaryUser}\n` : "") +
          (h.lastKnownIp ? `- Last known IP: ${h.lastKnownIp}\n` : "");
        return fetch(`/api/cases/${c.id}/notes`, {
          method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ content }),
        });
      }));
      showToast(`Added ${rows.length} host${rows.length !== 1 ? "s" : ""} to ${c.title} as notes.`);
      setCaseModalOpen(false);
      setSelected(new Set());
    } finally {
      setAddingToCase(false);
    }
  }

  async function isolateSelected() {
    setIsolating(true);
    const rows = sorted.filter((h) => selected.has(h.hostname));
    try {
      await Promise.all(rows.map((h) =>
        fetch(`/api/hosts/${encodeURIComponent(h.hostname)}`, {
          method: "PATCH", headers: { "content-type": "application/json" },
          body: JSON.stringify({ isolationStatus: "quarantined" }),
        })
      ));
      showToast(`Marked ${rows.length} host${rows.length !== 1 ? "s" : ""} as quarantined (tracking only).`);
      setIsolateConfirmOpen(false);
      setSelected(new Set());
      load();
    } finally {
      setIsolating(false);
    }
  }

  async function openPeek(hostname: string) {
    setPeekHostname(hostname);
    setPeekLoading(true);
    setPeekHost(null);
    setPeekCases([]);
    setPeekIocs([]);
    const res = await fetch(`/api/hosts/${encodeURIComponent(hostname)}`);
    if (res.ok) {
      const data = await res.json();
      setPeekHost(data.host);
      setPeekCases(data.cases ?? []);
      setPeekIocs(data.topIocs ?? []);
      setIsolationNoteDraft(data.host?.isolationNote ?? "");
    }
    setPeekLoading(false);
  }

  async function savePeekIsolation(status: IsolationStatus) {
    if (!peekHostname) return;
    setSavingIsolation(true);
    try {
      const res = await fetch(`/api/hosts/${encodeURIComponent(peekHostname)}`, {
        method: "PATCH", headers: { "content-type": "application/json" },
        body: JSON.stringify({ isolationStatus: status, isolationNote: isolationNoteDraft }),
      });
      if (res.ok) {
        const data = await res.json();
        setPeekHost((prev) => prev ? { ...prev, isolationStatus: status, isolationNote: isolationNoteDraft, isolationUpdatedAt: data.host.isolationUpdatedAt } : prev);
        showToast(`${peekHostname} marked ${status}.`);
        load();
      }
    } finally {
      setSavingIsolation(false);
    }
  }

  function SortHeader({ col }: { col: (typeof COLUMNS)[number] }) {
    const active = sortKey === col.key;
    return (
      <th
        title={col.title}
        onClick={() => toggleSort(col.key)}
        className={`cursor-pointer px-3 py-2.5 font-medium text-zinc-400 hover:text-zinc-200 select-none ${col.align === "right" ? "text-right" : "text-left"}`}
      >
        <span className={`inline-flex items-center gap-1 ${col.align === "right" ? "flex-row-reverse" : ""}`}>
          {col.label}
          {active ? (sortDir === "desc" ? <ArrowDown className="h-3 w-3 text-teal-400" /> : <ArrowUp className="h-3 w-3 text-teal-400" />) : <ArrowUpDown className="h-3 w-3 opacity-30" />}
        </span>
      </th>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">Host Profiles</h1>
          <p className="text-sm text-zinc-500 mt-0.5">Historical intelligence aggregated across all investigations</p>
        </div>
        <button onClick={() => load()} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-200">
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      <form onSubmit={handleSearch} className="mb-5">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by hostname, OS, or user…"
          className="w-full max-w-md rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
        />
      </form>

      {loading ? (
        <div className="text-center py-16 text-zinc-600">Loading host profiles…</div>
      ) : sorted.length === 0 ? (
        <div className="text-center py-16 text-zinc-600">
          <Monitor className="h-12 w-12 mx-auto mb-3 opacity-30" />
          {hosts.length === 0 ? (
            <p>No host profiles yet.</p>
          ) : (
            <p>No hosts match <span className="font-mono text-zinc-400">&ldquo;{q}&rdquo;</span>.</p>
          )}
        </div>
      ) : (
        <div className="rounded-xl border border-zinc-800 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900">
                <th className="w-10 px-3 py-2.5">
                  <input type="checkbox" checked={selected.size > 0 && selected.size === sorted.length} onChange={toggleSelectAll} className="rounded border-zinc-700 bg-zinc-950" />
                </th>
                <th className="text-left px-3 py-2.5 font-medium text-zinc-400">OS</th>
                {COLUMNS.slice(0, 1).map((c) => <SortHeader key={c.key} col={c} />)}
                <th className="text-left px-3 py-2.5 font-medium text-zinc-400">Primary User</th>
                <th className="text-left px-3 py-2.5 font-medium text-zinc-400">Last Known IP</th>
                {COLUMNS.slice(1).map((c) => <SortHeader key={c.key} col={c} />)}
                <th className="text-left px-3 py-2.5 font-medium text-zinc-400">Isolation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {sorted.map((h) => {
                const os = osMeta(h.osInfo);
                const iso = ISOLATION_META[h.isolationStatus];
                const IsoIcon = iso.icon;
                return (
                  <tr key={h.hostname} className="bg-zinc-950 hover:bg-zinc-900 transition-colors">
                    <td className="px-3 py-3">
                      <input type="checkbox" checked={selected.has(h.hostname)} onChange={() => toggleSelect(h.hostname)} className="rounded border-zinc-700 bg-zinc-950" />
                    </td>
                    <td className="px-3 py-3" title={os.label}>
                      <os.Icon className="h-4 w-4 text-zinc-500" />
                    </td>
                    <td className="px-3 py-3">
                      <button onClick={() => openPeek(h.hostname)} className="font-mono text-teal-400 hover:text-teal-300 text-left">
                        {h.hostname}
                      </button>
                    </td>
                    <td className="px-3 py-3 text-zinc-400">
                      {h.primaryUser ? <span className="inline-flex items-center gap-1"><UserIcon className="h-3 w-3 text-zinc-600" />{h.primaryUser}</span> : <span className="text-zinc-700">—</span>}
                    </td>
                    <td className="px-3 py-3 font-mono text-xs text-zinc-400">
                      {h.lastKnownIp ?? <span className="text-zinc-700">—</span>}
                    </td>
                    <td className="px-3 py-3 text-right">
                      <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-semibold ${RISK_META[h.riskTier].cls}`}>
                        {h.riskTier === "critical" && <AlertTriangle className="h-3 w-3" />}
                        {RISK_META[h.riskTier].label}
                      </span>
                    </td>
                    <td className="px-3 py-3 text-right text-zinc-400">{h.investigationCount}</td>
                    <td className="px-3 py-3 text-right">
                      <span className="text-zinc-300">{h.findingCount}</span>
                      {h.criticalCount > 0 && (
                        <span className="ml-1.5 inline-flex items-center gap-0.5 rounded-full border border-red-500/40 bg-red-500/15 px-1.5 py-0.5 text-[11px] font-bold text-red-400">
                          <AlertTriangle className="h-2.5 w-2.5" /> {h.criticalCount}
                        </span>
                      )}
                    </td>
                    <td className={`px-3 py-3 text-right ${muted(h.iocMatchCount, "text-zinc-300")}`}>{h.iocMatchCount}</td>
                    <td className={`px-3 py-3 text-right ${muted(h.usbActivity, "text-zinc-300")}`}>{h.usbActivity}</td>
                    <td className={`px-3 py-3 text-right ${muted(h.persistenceEvents, "text-zinc-300")}`}>{h.persistenceEvents}</td>
                    <td className="px-3 py-3 text-right text-zinc-500">{new Date(h.lastSeen).toLocaleDateString()}</td>
                    <td className="px-3 py-3">
                      <span className={`inline-flex items-center gap-1 text-xs ${iso.cls}`} title={h.isolationUpdatedAt ? `Updated ${new Date(h.isolationUpdatedAt).toLocaleString()}${h.isolationUpdatedBy ? ` by ${h.isolationUpdatedBy.name ?? h.isolationUpdatedBy.email}` : ""}` : "Manually tracked — not a live network action"}>
                        <IsoIcon className="h-3.5 w-3.5" /> {iso.label}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Floating bulk action bar */}
      {selected.size > 0 && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-30 flex items-center gap-3 rounded-xl border border-zinc-700 bg-zinc-900 px-4 py-3 shadow-2xl">
          <span className="text-sm text-zinc-300">{selected.size} selected</span>
          <button onClick={exportCsv} className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800">
            <Download className="h-3.5 w-3.5" /> Export CSV
          </button>
          <button onClick={() => setCaseModalOpen(true)} className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800">
            <FolderPlus className="h-3.5 w-3.5" /> Add to Case
          </button>
          <button onClick={() => setIsolateConfirmOpen(true)} className="flex items-center gap-1.5 rounded-md border border-orange-700/50 bg-orange-500/10 px-3 py-1.5 text-xs text-orange-300 hover:bg-orange-500/20">
            <ShieldOff className="h-3.5 w-3.5" /> Isolate Hosts
          </button>
          <button onClick={() => setSelected(new Set())} className="text-zinc-600 hover:text-zinc-300">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Add to Case modal */}
      {caseModalOpen && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4" onClick={() => setCaseModalOpen(false)}>
          <div className="w-full max-w-md rounded-xl border border-zinc-700 bg-zinc-950 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
              <h3 className="text-sm font-semibold text-zinc-200">Add {selected.size} host{selected.size !== 1 ? "s" : ""} to a case</h3>
              <button onClick={() => setCaseModalOpen(false)} className="text-zinc-600 hover:text-zinc-300"><X className="h-4 w-4" /></button>
            </div>
            <div className="p-4">
              <div className="flex items-center gap-2 mb-2 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2">
                <Search className="h-3.5 w-3.5 text-zinc-500" />
                <input
                  autoFocus
                  value={caseSearch}
                  onChange={(e) => setCaseSearch(e.target.value)}
                  placeholder="Search cases…"
                  className="flex-1 bg-transparent text-sm text-zinc-200 placeholder-zinc-600 outline-none"
                />
              </div>
              <div className="max-h-56 overflow-y-auto space-y-1">
                {caseOptions.length === 0 ? (
                  <p className="text-xs text-zinc-600 text-center py-4">No cases found.</p>
                ) : caseOptions.map((c) => (
                  <button
                    key={c.id}
                    disabled={addingToCase}
                    onClick={() => addSelectedToCase(c)}
                    className="w-full flex items-center justify-between rounded-md px-3 py-2 text-left text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-50"
                  >
                    <span className="truncate">
                      <span className="font-mono text-xs text-zinc-500 mr-1.5">{formatCaseNumber(c.caseSeq)}</span>
                      {c.title}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Isolate confirmation */}
      {isolateConfirmOpen && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4" onClick={() => setIsolateConfirmOpen(false)}>
          <div className="w-full max-w-md rounded-xl border border-zinc-700 bg-zinc-950 p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-zinc-200 mb-2">Mark {selected.size} host{selected.size !== 1 ? "s" : ""} as quarantined?</h3>
            <p className="text-xs text-zinc-500 mb-4">
              Forensicator has no EDR/agent integration — this only records that containment action was taken
              elsewhere (e.g. via your EDR console). It does not isolate anything on the network.
            </p>
            <div className="flex justify-end gap-2">
              <button onClick={() => setIsolateConfirmOpen(false)} className="rounded-md border border-zinc-700 px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-200">Cancel</button>
              <button onClick={isolateSelected} disabled={isolating} className="rounded-md bg-orange-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-orange-500 disabled:opacity-50">
                {isolating ? "Marking…" : "Mark Quarantined"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Quick Peek drawer */}
      {peekHostname && (
        <div className="fixed inset-0 z-40 flex justify-end">
          <div className="flex-1 bg-black/50" onClick={() => setPeekHostname(null)} />
          <div className="w-full max-w-md h-full overflow-y-auto border-l border-zinc-800 bg-zinc-950 shadow-2xl">
            <div className="sticky top-0 flex items-center justify-between border-b border-zinc-800 bg-zinc-950 px-4 py-3">
              <h3 className="font-mono text-sm font-semibold text-zinc-100">{peekHostname}</h3>
              <button onClick={() => setPeekHostname(null)} className="text-zinc-600 hover:text-zinc-300"><X className="h-4 w-4" /></button>
            </div>
            {peekLoading ? (
              <div className="p-6 text-center text-zinc-600 text-sm">Loading…</div>
            ) : !peekHost ? (
              <div className="p-6 text-center text-zinc-600 text-sm">Could not load host.</div>
            ) : (
              <div className="p-4 space-y-5">
                <div className="flex items-center gap-2">
                  <span className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-semibold ${RISK_META[peekHost.riskTier].cls}`}>
                    {RISK_META[peekHost.riskTier].label} risk ({peekHost.riskScore})
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  {[
                    { label: "Investigations", value: peekHost.investigationCount },
                    { label: "Findings", value: peekHost.findingCount },
                    { label: "Critical", value: peekHost.criticalCount },
                    { label: "IOC Hits", value: peekHost.iocMatchCount },
                    { label: "USB Events", value: peekHost.usbActivity },
                    { label: "Persistence", value: peekHost.persistenceEvents },
                  ].map(({ label, value }) => (
                    <div key={label} className="rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2">
                      <div className={`text-lg font-bold ${value === 0 ? "text-zinc-700" : "text-zinc-100"}`}>{value}</div>
                      <div className="text-[11px] text-zinc-500">{label}</div>
                    </div>
                  ))}
                </div>

                <div className="text-xs text-zinc-400 space-y-1">
                  <p className="flex items-center gap-1.5"><UserIcon className="h-3.5 w-3.5 text-zinc-600" /> Primary user: {peekHost.primaryUser ?? "—"}</p>
                  <p className="flex items-center gap-1.5"><Network className="h-3.5 w-3.5 text-zinc-600" /> Last known IP: {peekHost.lastKnownIp ?? "—"}</p>
                </div>

                <div>
                  <p className="text-xs font-semibold text-zinc-400 mb-1.5">Containment status (manually tracked)</p>
                  <div className="flex gap-1.5 mb-2">
                    {(["active", "quarantined", "offline"] as IsolationStatus[]).map((s) => (
                      <button
                        key={s}
                        onClick={() => savePeekIsolation(s)}
                        disabled={savingIsolation}
                        className={`flex-1 rounded-md border px-2 py-1.5 text-xs ${
                          peekHost.isolationStatus === s ? ISOLATION_META[s].cls + " border-current" : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
                        }`}
                      >
                        {ISOLATION_META[s].label}
                      </button>
                    ))}
                  </div>
                  <textarea
                    value={isolationNoteDraft}
                    onChange={(e) => setIsolationNoteDraft(e.target.value)}
                    onBlur={() => savePeekIsolation(peekHost.isolationStatus)}
                    placeholder="Optional note (e.g. how/when contained)…"
                    rows={2}
                    className="w-full rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-1.5 text-xs text-zinc-300 placeholder-zinc-600 outline-none focus:border-teal-500"
                  />
                </div>

                {peekIocs.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-zinc-400 mb-1.5">Most severe known IOCs</p>
                    <div className="space-y-1">
                      {peekIocs.map((ioc) => (
                        <Link
                          key={ioc.value}
                          href={`/intelligence/ioc/${encodeURIComponent(ioc.value)}`}
                          className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-1.5 hover:border-red-500/40"
                        >
                          <span className="font-mono text-xs text-zinc-300 truncate">{ioc.value}</span>
                          {ioc.reputation !== null && <span className="text-xs text-red-400 shrink-0 ml-2">{ioc.reputation}/100</span>}
                        </Link>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <p className="text-xs font-semibold text-zinc-400 mb-1.5">Cases ({peekCases.length})</p>
                  {peekCases.length === 0 ? (
                    <p className="text-xs text-zinc-600">No linked cases.</p>
                  ) : (
                    <div className="space-y-1">
                      {peekCases.map((c) => (
                        <Link key={c.id} href={`/cases/${c.id}`} className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-1.5 hover:border-teal-600/50">
                          <span className="text-xs text-zinc-300 truncate">
                            <span className="font-mono text-zinc-500 mr-1">{formatCaseNumber(c.caseSeq)}</span>{c.title}
                          </span>
                          <span className="text-[10px] text-zinc-600 shrink-0 ml-2">{c.status}</span>
                        </Link>
                      ))}
                    </div>
                  )}
                </div>

                <Link
                  href={`/hosts/${encodeURIComponent(peekHostname)}`}
                  className="block text-center rounded-md border border-zinc-700 px-3 py-2 text-sm text-teal-400 hover:bg-zinc-900"
                >
                  Open Full Profile →
                </Link>
              </div>
            )}
          </div>
        </div>
      )}

      {toast && (
        <div className="fixed bottom-24 left-1/2 -translate-x-1/2 z-30 rounded-md border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm text-zinc-200 shadow-xl">
          {toast}
        </div>
      )}
    </div>
  );
}
