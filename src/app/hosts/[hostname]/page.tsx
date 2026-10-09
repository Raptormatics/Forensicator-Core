"use client";

import { useEffect, useState, useCallback } from "react";
import { createPortal } from "react-dom";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft, RefreshCw, Cpu, Network, Globe2, User as UserIcon, Fingerprint,
  ShieldOff, ShieldCheck, ShieldQuestion, AlertTriangle, Copy, Check, MoreVertical,
  Clock3, Waypoints, FolderKanban,
} from "lucide-react";
import { formatCaseNumber } from "@/lib/cases/case-number";
import { severityClassName } from "@/lib/severity";
import { RISK_META, ISOLATION_LABEL, ISOLATION_CLASS, type RiskTier, type IsolationStatus } from "@/lib/hosts/risk-ui";

type HostProfile = {
  hostname: string;
  osInfo: unknown | null;
  riskScore: number;
  riskTier: RiskTier;
  firstSeen: string;
  lastSeen: string;
  investigationCount: number;
  findingCount: number;
  criticalCount: number;
  highCount: number;
  iocMatchCount: number;
  usbActivity: number;
  persistenceEvents: number;
  primaryUser: string | null;
  lastKnownIp: string | null;
  macAddress: string | null;
  domain: string | null;
  isolationStatus: IsolationStatus;
  isolationNote: string | null;
  isolationUpdatedAt: string | null;
  isolationUpdatedBy: { email: string; name: string | null } | null;
};

type CaseRef = { id: string; title: string; caseSeq: number; status: string; severity: string };

type InvSummary = {
  id: string;
  hostname: string | null;
  title: string;
  status: string;
  aiStatus: string;
  createdAt: string;
  findingCount: number | null;
  case: CaseRef | null;
  hasAttackPath: boolean;
  deltaFindings: number | null;
  deltaIocs: number | null;
};

const AI_STATUS_META: Record<string, { label: string; cls: string }> = {
  not_queued: { label: "Not analyzed", cls: "text-zinc-600" },
  processing: { label: "AI analyzing…", cls: "text-yellow-400" },
  complete:   { label: "AI analyzed",   cls: "text-teal-400" },
  failed:     { label: "AI failed",     cls: "text-red-400" },
};

const ISOLATION_ICON: Record<IsolationStatus, typeof ShieldCheck> = {
  active: ShieldQuestion,
  quarantined: ShieldOff,
  offline: ShieldCheck,
};

function osLabel(osInfo: unknown): string {
  return typeof osInfo === "object" && osInfo !== null
    ? String((osInfo as Record<string, unknown>).platform ?? "Unknown")
    : "Unknown";
}

function DeltaBadge({ value, label }: { value: number | null; label: string }) {
  if (value === null) return <span className="text-[10px] text-zinc-700" title="First collection for this host — no prior baseline">baseline</span>;
  if (value === 0) return <span className="text-[10px] text-zinc-700">±0 {label}</span>;
  const up = value > 0;
  return (
    <span className={`text-[10px] font-medium ${up ? "text-orange-400" : "text-zinc-500"}`} title={`${up ? "+" : ""}${value} ${label} vs. the previous collection for this host`}>
      {up ? "+" : ""}{value} {label}
    </span>
  );
}

export default function HostDetailPage() {
  const { hostname: encodedHostname } = useParams<{ hostname: string }>();
  const hostname = decodeURIComponent(encodedHostname);

  const [host, setHost]                     = useState<HostProfile | null>(null);
  const [investigations, setInvestigations] = useState<InvSummary[]>([]);
  const [cases, setCases]                   = useState<CaseRef[]>([]);
  const [loading, setLoading]               = useState(true);
  const [syncing, setSyncing]               = useState(false);

  const [copiedId, setCopiedId] = useState<string | null>(null);
  // The row menu is rendered through a portal (see below) so it isn't
  // clipped by the investigation table's `overflow-x-auto` wrapper — it
  // needs its own fixed-position coordinates rather than relying on
  // `position: absolute` inside the row.
  const [rowMenuOpen, setRowMenuOpen] = useState<{ id: string; top: number; left: number } | null>(null);
  const [isolatePanelOpen, setIsolatePanelOpen] = useState(false);
  const [isolationNoteDraft, setIsolationNoteDraft] = useState("");
  const [savingIsolation, setSavingIsolation] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => { setMounted(true); }, []);

  // Close the menu on scroll rather than repositioning it — it's a
  // short-lived popup, not worth tracking scroll offsets for.
  useEffect(() => {
    if (!rowMenuOpen) return;
    const close = () => setRowMenuOpen(null);
    window.addEventListener("scroll", close, true);
    return () => window.removeEventListener("scroll", close, true);
  }, [rowMenuOpen]);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await fetch(`/api/hosts/${encodeURIComponent(hostname)}`);
    if (res.ok) {
      const data = await res.json();
      setHost(data.host);
      setInvestigations(data.investigations ?? []);
      setCases(data.cases ?? []);
      setIsolationNoteDraft(data.host?.isolationNote ?? "");
    }
    setLoading(false);
  }, [hostname]);

  async function sync() {
    setSyncing(true);
    await fetch(`/api/hosts/${encodeURIComponent(hostname)}/sync`, { method: "POST" });
    setSyncing(false);
    load();
  }

  async function setIsolation(status: IsolationStatus) {
    setSavingIsolation(true);
    try {
      const res = await fetch(`/api/hosts/${encodeURIComponent(hostname)}`, {
        method: "PATCH", headers: { "content-type": "application/json" },
        body: JSON.stringify({ isolationStatus: status, isolationNote: isolationNoteDraft }),
      });
      if (res.ok) {
        const data = await res.json();
        setHost((prev) => prev ? { ...prev, isolationStatus: status, isolationNote: isolationNoteDraft, isolationUpdatedAt: data.host.isolationUpdatedAt } : prev);
      }
    } finally {
      setSavingIsolation(false);
    }
  }

  function copyId(id: string) {
    navigator.clipboard.writeText(id).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId((cur) => (cur === id ? null : cur)), 1500);
    });
  }

  useEffect(() => { if (hostname) load(); }, [hostname, load]);

  if (loading) return <div className="p-8 text-zinc-500">Loading…</div>;

  return (
    <div className="p-6 max-w-5xl mx-auto" onClick={() => setRowMenuOpen(null)}>
      <Link href="/hosts" className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300 mb-4">
        <ArrowLeft className="h-4 w-4" /> Hosts
      </Link>

      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between mb-6">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <Cpu className="h-5 w-5 text-teal-400 shrink-0" />
            <h1 className="text-2xl font-bold font-mono text-zinc-100 break-all">{hostname}</h1>
            {host && (
              <span className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${RISK_META[host.riskTier].cls}`}>
                {host.riskTier === "critical" && <AlertTriangle className="h-3 w-3" />}
                {RISK_META[host.riskTier].label} risk
              </span>
            )}
          </div>
          <p className="text-sm text-zinc-500 mt-0.5">{host ? osLabel(host.osInfo) : ""}</p>

          {host && (
            <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5 text-xs text-zinc-400">
              <span className="flex items-center gap-1.5"><Network className="h-3.5 w-3.5 text-zinc-600" /> Last IP: {host.lastKnownIp ?? <span className="text-zinc-700">—</span>}</span>
              <span className="flex items-center gap-1.5"><Globe2 className="h-3.5 w-3.5 text-zinc-600" /> Domain: {host.domain ?? <span className="text-zinc-700">—</span>}</span>
              <span className="flex items-center gap-1.5"><UserIcon className="h-3.5 w-3.5 text-zinc-600" /> User: {host.primaryUser ?? <span className="text-zinc-700">—</span>}</span>
              <span className="flex items-center gap-1.5"><Fingerprint className="h-3.5 w-3.5 text-zinc-600" /> MAC: {host.macAddress ?? <span className="text-zinc-700">—</span>}</span>
            </div>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-2 relative">
          <div className="relative">
            <button
              onClick={(e) => { e.stopPropagation(); setIsolatePanelOpen((v) => !v); }}
              className={`flex items-center gap-1.5 rounded-md border px-3 py-2 text-sm font-medium ${
                host?.isolationStatus === "quarantined" ? "border-orange-700/50 bg-orange-500/10 text-orange-300" : "border-zinc-700 bg-zinc-900 text-zinc-300 hover:bg-zinc-800"
              }`}
            >
              <ShieldOff className="h-4 w-4" /> {host ? ISOLATION_LABEL[host.isolationStatus] : "Isolate Host"}
            </button>
            {isolatePanelOpen && host && (
              <div onClick={(e) => e.stopPropagation()} className="absolute right-0 top-full z-20 mt-2 w-72 rounded-lg border border-zinc-700 bg-zinc-950 shadow-xl p-3">
                <p className="text-xs text-zinc-500 mb-2">
                  Manually tracked containment state — Forensicator has no EDR/agent integration, so this records
                  action taken elsewhere. It does not isolate anything on the network.
                </p>
                <div className="flex gap-1.5 mb-2">
                  {(["active", "quarantined", "offline"] as IsolationStatus[]).map((s) => (
                    <button
                      key={s}
                      onClick={() => setIsolation(s)}
                      disabled={savingIsolation}
                      className={`flex-1 rounded-md border px-2 py-1.5 text-xs ${
                        host.isolationStatus === s ? `border-current ${ISOLATION_CLASS[s]}` : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
                      }`}
                    >
                      {ISOLATION_LABEL[s]}
                    </button>
                  ))}
                </div>
                <textarea
                  value={isolationNoteDraft}
                  onChange={(e) => setIsolationNoteDraft(e.target.value)}
                  onBlur={() => setIsolation(host.isolationStatus)}
                  placeholder="Optional note…"
                  rows={2}
                  className="w-full rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-1.5 text-xs text-zinc-300 placeholder-zinc-600 outline-none focus:border-teal-500"
                />
                {host.isolationUpdatedAt && (
                  <p className="text-[10px] text-zinc-600 mt-1.5">
                    Updated {new Date(host.isolationUpdatedAt).toLocaleString()}{host.isolationUpdatedBy ? ` by ${host.isolationUpdatedBy.name ?? host.isolationUpdatedBy.email}` : ""}
                  </p>
                )}
              </div>
            )}
          </div>
          <button onClick={sync} disabled={syncing} title="Refreshes the org-wide Host Profiles list cache — this page always shows live data" className="flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-50">
            <RefreshCw className={`h-4 w-4 ${syncing ? "animate-spin" : ""}`} />
            {syncing ? "Syncing…" : "Sync Profile"}
          </button>
        </div>
      </div>

      {/* KPI strip — dense, Risk moved to the header badge above */}
      {host && (
        <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-7 gap-2 mb-6">
          {[
            { label: "Investigations", value: host.investigationCount, highlight: false, severity: null },
            { label: "Findings",       value: host.findingCount,       highlight: false, severity: null },
            { label: "Important",      value: host.criticalCount,      highlight: host.criticalCount > 0, severity: "important" as const },
            { label: "Notable",        value: host.highCount,          highlight: host.highCount > 0,     severity: "notable" as const },
            { label: "IOC Matches",    value: host.iocMatchCount,      highlight: host.iocMatchCount > 0, severity: null },
            { label: "USB Events",     value: host.usbActivity,        highlight: host.usbActivity > 0, severity: null },
            { label: "Persistence",    value: host.persistenceEvents,  highlight: host.persistenceEvents > 0, severity: null, title: "Autorun keys, scheduled tasks, services, startup items" },
          ].map(({ label, value, highlight, severity, title }) => (
            <div key={label} title={title} className="rounded-lg border border-zinc-800 bg-zinc-900 px-2.5 py-2 text-center">
              {severity ? (
                <div className={`inline-flex items-center rounded-full border px-2 py-0.5 text-lg font-bold ${value === 0 ? "border-zinc-700 text-zinc-700" : severityClassName(severity)}`}>{value}</div>
              ) : (
                <div className={`text-lg font-bold ${value === 0 ? "text-zinc-700" : highlight ? "text-red-400" : "text-zinc-100"}`}>{value}</div>
              )}
              <div className="text-[11px] text-zinc-500 mt-0.5">{label}</div>
            </div>
          ))}
        </div>
      )}
      <p className="text-[11px] text-zinc-600 -mt-4 mb-6">
        &ldquo;Important&rdquo;/&ldquo;Notable&rdquo; are Forensicator&rsquo;s evidentiary-severity scale (roughly Critical/High) — the same vocabulary used across Cases and Findings platform-wide.
      </p>

      {cases.length > 0 && (
        <div className="grid grid-cols-1 gap-4 mb-6">
          <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <h2 className="text-sm font-semibold text-zinc-300 mb-3 flex items-center gap-1.5"><FolderKanban className="h-4 w-4 text-teal-400" /> Cases ({cases.length})</h2>
            <div className="space-y-1.5">
              {cases.map((c) => (
                <Link key={c.id} href={`/cases/${c.id}`} className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 hover:border-teal-600/50">
                  <span className="text-xs text-zinc-300 truncate"><span className="font-mono text-zinc-500 mr-1">{formatCaseNumber(c.caseSeq)}</span>{c.title}</span>
                  <span className="text-[10px] text-zinc-600 shrink-0 ml-2">{c.status}</span>
                </Link>
              ))}
            </div>
          </section>
        </div>
      )}

      <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
        <h2 className="text-sm font-semibold text-zinc-300 mb-3">Investigation History ({investigations.length})</h2>
        {investigations.length === 0 ? (
          <p className="text-sm text-zinc-600">No investigations found for this host.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-left">
                  <th className="pb-2 pr-4 font-medium text-zinc-400">Investigation</th>
                  <th className="pb-2 pr-4 font-medium text-zinc-400">Analysis Status</th>
                  <th className="pb-2 pr-4 font-medium text-zinc-400">Created</th>
                  <th className="pb-2 pr-4 text-right font-medium text-zinc-400">Findings</th>
                  <th className="pb-2 pr-2 w-8"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {investigations.map((inv) => {
                  const aiMeta = AI_STATUS_META[inv.aiStatus] ?? AI_STATUS_META.not_queued;
                  return (
                    <tr key={inv.id} className="hover:bg-zinc-800/50 transition-colors">
                      <td className="py-2.5 pr-4">
                        <Link href={`/investigations/${inv.id}`} className="text-sm text-teal-400 hover:text-teal-300 truncate block max-w-xs">
                          {inv.title}
                        </Link>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          {inv.case && (
                            <Link href={`/cases/${inv.case.id}`} className="text-[10px] font-mono text-zinc-500 hover:text-zinc-300">
                              {formatCaseNumber(inv.case.caseSeq)}
                            </Link>
                          )}
                          <button onClick={() => copyId(inv.id)} title="Copy investigation ID" className="text-zinc-700 hover:text-zinc-400">
                            {copiedId === inv.id ? <Check className="h-3 w-3 text-teal-400" /> : <Copy className="h-3 w-3" />}
                          </button>
                        </div>
                      </td>
                      <td className="py-2.5 pr-4">
                        <span className={`text-xs ${aiMeta.cls}`}>{aiMeta.label}</span>
                        {inv.hasAttackPath && <span className="ml-2 text-[10px] text-indigo-400">ATT&amp;CK mapped</span>}
                      </td>
                      <td className="py-2.5 pr-4 text-zinc-500 whitespace-nowrap">{new Date(inv.createdAt).toLocaleDateString()}</td>
                      <td className="py-2.5 pr-4 text-right">
                        <div className="text-zinc-300">{inv.findingCount ?? "—"}</div>
                        <DeltaBadge value={inv.deltaFindings} label="findings" />
                      </td>
                      <td className="py-2.5 pr-2 relative">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            if (rowMenuOpen?.id === inv.id) {
                              setRowMenuOpen(null);
                              return;
                            }
                            const rect = e.currentTarget.getBoundingClientRect();
                            setRowMenuOpen({ id: inv.id, top: rect.bottom + 4, left: rect.right - 192 });
                          }}
                          className="p-1 rounded text-zinc-600 hover:text-zinc-200 hover:bg-zinc-800"
                        >
                          <MoreVertical className="h-4 w-4" />
                        </button>
                        {mounted && rowMenuOpen?.id === inv.id && createPortal(
                          <div
                            onClick={(e) => e.stopPropagation()}
                            style={{ position: "fixed", top: rowMenuOpen.top, left: rowMenuOpen.left }}
                            className="z-50 w-48 rounded-lg border border-zinc-700 bg-zinc-950 shadow-xl overflow-hidden py-1"
                          >
                            <Link href={`/investigations/${inv.id}/timeline`} className="flex items-center gap-2 px-3 py-2 text-xs text-zinc-300 hover:bg-zinc-800">
                              <Clock3 className="h-3.5 w-3.5" /> View Timeline
                            </Link>
                            <Link href={`/investigations/${inv.id}/artifacts`} className="flex items-center gap-2 px-3 py-2 text-xs text-zinc-300 hover:bg-zinc-800">
                              <Fingerprint className="h-3.5 w-3.5" /> View Artifacts
                            </Link>
                            <Link href={`/investigations/${inv.id}/attack-path`} className="flex items-center gap-2 px-3 py-2 text-xs text-zinc-300 hover:bg-zinc-800">
                              <Waypoints className="h-3.5 w-3.5" /> Map to ATT&amp;CK Matrix
                            </Link>
                          </div>,
                          document.body
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
