"use client";

import { useEffect, useState, useCallback, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { useSession } from "next-auth/react";
import Link from "next/link";
import { RefreshCw, ShieldAlert, Search, UserCheck } from "lucide-react";
import { normalizeSeverity, severityClassName, SEVERITY_LABELS } from "@/lib/severity";
import { formatCaseNumber } from "@/lib/cases/case-number";

type CaseRef = { id: string; title: string; caseSeq: number };
type Finding = {
  id: string;
  findingType: string;
  category: string;
  severity: string;
  workflowStatus: string;
  createdAt: string;
  assignee: { id: string; name: string | null; email: string } | null;
  investigation: { id: string; title: string; hostname: string | null; case: CaseRef | null };
};

const STATUS_OPTIONS = ["new", "under_review", "confirmed", "escalated", "resolved", "false_positive"];
const STATUS_LABEL: Record<string, string> = {
  new: "New", under_review: "Under Review", confirmed: "Confirmed",
  false_positive: "False Positive", escalated: "Escalated", resolved: "Resolved",
};
const STATUS_COLOR: Record<string, string> = {
  new: "bg-zinc-700 text-zinc-200",
  under_review: "bg-blue-900/50 text-blue-300",
  confirmed: "bg-red-900/50 text-red-300",
  false_positive: "bg-zinc-800 text-zinc-400 line-through",
  escalated: "bg-orange-900/50 text-orange-300",
  resolved: "bg-green-900/50 text-green-400",
};

const LIMIT = 50;

function FindingsTriage() {
  const searchParams = useSearchParams();

  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [page, setPage]         = useState(1);
  const [q, setQ]               = useState("");
  const [qInput, setQInput]     = useState("");
  const [statusFilter, setStatusFilter]     = useState<string[]>(() => (searchParams.get("status")?.split(",").filter(Boolean)) ?? []);
  const [assigneeFilter, setAssigneeFilter] = useState<string>(searchParams.get("assignee") ?? "");
  const [severityFilter, setSeverityFilter] = useState<string[]>(() => (searchParams.get("severity")?.split(",").filter(Boolean)) ?? []);
  const [savingId, setSavingId] = useState<string | null>(null);
  const { data: session } = useSession();
  const meId = (session?.user?.id as string | undefined) ?? null;

  const load = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({ page: String(page), limit: String(LIMIT) });
    if (q) params.set("q", q);
    if (statusFilter.length > 0) params.set("status", statusFilter.join(","));
    if (assigneeFilter) params.set("assignee", assigneeFilter);
    if (severityFilter.length > 0) params.set("severity", severityFilter.join(","));
    const res = await fetch(`/api/findings?${params}`);
    if (res.ok) {
      const data = await res.json();
      setFindings(data.findings ?? []);
      setTotal(data.total ?? 0);
    }
    setLoading(false);
  }, [page, q, statusFilter, assigneeFilter, severityFilter]);

  useEffect(() => { load(); }, [load]);

  function toggleStatus(s: string) {
    setPage(1);
    setStatusFilter((prev) => prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]);
  }
  function toggleSeverity(s: string) {
    setPage(1);
    setSeverityFilter((prev) => prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]);
  }

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    setQ(qInput);
  }

  async function assignToMe(f: Finding) {
    if (!meId) return;
    setSavingId(f.id);
    await fetch(`/api/findings/${f.id}/assign`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ assigneeId: meId }),
    });
    setSavingId(null);
    load();
  }

  async function changeStatus(f: Finding, status: string) {
    setSavingId(f.id);
    await fetch(`/api/findings/${f.id}/status`, {
      method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ status }),
    });
    setSavingId(null);
    load();
  }

  const totalPages = Math.max(1, Math.ceil(total / LIMIT));

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2"><ShieldAlert className="h-6 w-6 text-orange-400" /> Findings Triage</h1>
          <p className="text-sm text-zinc-500 mt-0.5">Findings across every investigation, filterable by status, assignee, and severity</p>
        </div>
        <button onClick={load} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-200">
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 mb-4 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <form onSubmit={handleSearch} className="relative flex-1 min-w-[220px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
            <input
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              placeholder="Search finding type or category…"
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 pl-8 pr-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
            />
          </form>
          <div className="flex items-center gap-1.5">
            {[
              { value: "", label: "Anyone" },
              { value: "me", label: "Assigned to me" },
              { value: "unassigned", label: "Unassigned" },
            ].map((o) => (
              <button
                key={o.value}
                onClick={() => { setAssigneeFilter(o.value); setPage(1); }}
                className={`rounded-md px-2.5 py-1.5 text-xs font-medium border ${
                  assigneeFilter === o.value ? "border-teal-600 bg-teal-500/10 text-teal-400" : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {o.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-zinc-600">Status:</span>
          {STATUS_OPTIONS.map((s) => (
            <button
              key={s}
              onClick={() => toggleStatus(s)}
              className={`rounded-full px-2.5 py-1 text-xs font-medium border ${
                statusFilter.includes(s) ? "border-teal-600 bg-teal-500/10 text-teal-400" : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {STATUS_LABEL[s]}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-zinc-600">Severity:</span>
          {SEVERITY_LABELS.map((s) => (
            <button
              key={s}
              onClick={() => toggleSeverity(s)}
              className={`rounded-full px-2.5 py-1 text-xs font-medium border ${
                severityFilter.includes(s) ? severityClassName(s) : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </section>

      {loading ? (
        <div className="text-center py-16 text-zinc-600">Loading findings…</div>
      ) : findings.length === 0 ? (
        <div className="text-center py-16 text-zinc-600">
          <ShieldAlert className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p>No findings match these filters.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {findings.map((f) => (
            <div key={f.id} className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2.5">
              <span className={`shrink-0 inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${severityClassName(f.severity)}`}>
                {normalizeSeverity(f.severity)}
              </span>
              <div className="min-w-0 flex-1">
                <Link href={`/investigations/${f.investigation.id}`} className="truncate text-sm text-zinc-200 hover:text-teal-300 block">
                  {f.findingType}
                </Link>
                <p className="truncate text-xs text-zinc-500">
                  {f.investigation.hostname ?? f.investigation.title}
                  {f.investigation.case && (
                    <>
                      {" · "}
                      <Link href={`/cases/${f.investigation.case.id}`} onClick={(e) => e.stopPropagation()} className="text-teal-600 hover:text-teal-400">
                        {formatCaseNumber(f.investigation.case.caseSeq)}
                      </Link>
                    </>
                  )}
                </p>
              </div>
              <select
                value={f.workflowStatus}
                onChange={(e) => changeStatus(f, e.target.value)}
                disabled={savingId === f.id}
                className={`shrink-0 rounded px-2 py-1 text-xs font-medium border-none outline-none ${STATUS_COLOR[f.workflowStatus] ?? "bg-zinc-700 text-zinc-300"}`}
              >
                {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
              </select>
              {f.assignee ? (
                <span className="shrink-0 text-xs text-zinc-500 w-28 truncate text-right">{f.assignee.name ?? f.assignee.email}</span>
              ) : (
                <button onClick={() => assignToMe(f)} disabled={savingId === f.id || !meId} className="shrink-0 flex items-center gap-1 text-xs text-teal-400 hover:text-teal-300 disabled:opacity-50">
                  <UserCheck className="h-3.5 w-3.5" /> Assign to me
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {total > LIMIT && (
        <div className="flex gap-2 mt-4 justify-center items-center">
          <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} className="rounded px-3 py-1 text-sm border border-zinc-800 text-zinc-500 disabled:opacity-30">Previous</button>
          <span className="px-3 py-1 text-sm text-zinc-500">Page {page} of {totalPages} · {total} total</span>
          <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages} className="rounded px-3 py-1 text-sm border border-zinc-800 text-zinc-500 disabled:opacity-30">Next</button>
        </div>
      )}
    </div>
  );
}

export default function FindingsPage() {
  return (
    <Suspense>
      <FindingsTriage />
    </Suspense>
  );
}
