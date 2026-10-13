"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, Link2, Search, Trash2, RefreshCw, ListChecks, ChevronDown, ChevronUp, Plus, X } from "lucide-react";
import { formatCaseNumber } from "@/lib/cases/case-number";
import { ReportGenerator } from "@/components/reports/report-generator";
import { AssigneePanel } from "@/components/shared/assignee-panel";
import { CaseThreatIntelSection } from "@/components/cases/case-threat-intel-section";

type CaseDetail = {
  id: string;
  caseSeq: number;
  title: string;
  description: string | null;
  status: string;
  severity: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  createdBy: { email: string; name: string | null } | null;
  assignee:  { id: string; email: string; name: string | null } | null;
  notes: { id: string; content: string; createdAt: string; author: { email: string; name: string | null } }[];
  investigations: { id: string; title: string; hostname: string | null; status: string; findingCount: number }[];
};

type InvOption = { id: string; title: string | null; hostname: string | null; status: string; findingCount: number; createdAt: string; caseId: string | null };

type TaskUser = { id: string; email: string; name: string | null };
type RelatedFinding = { id: string; findingId: string; findingType: string; category: string; severity: string; investigation: { id: string; hostname: string | null } };
type CaseTask = {
  id: string;
  title: string;
  notes: string | null;
  status: "todo" | "in_progress" | "done";
  priority: "critical" | "high" | "medium" | "low";
  dueAt: string | null;
  owner: TaskUser | null;
  createdBy: TaskUser | null;
  relatedFindingIds: string[];
  createdAt: string;
};

const TASK_PRIORITY_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high:     "text-orange-400",
  medium:   "text-yellow-400",
  low:      "text-blue-400",
};

const TASK_STATUS_OPTS: { value: CaseTask["status"]; label: string; color: string }[] = [
  { value: "todo",        label: "To Do",       color: "border-zinc-700 bg-zinc-900 text-zinc-300 hover:border-zinc-500" },
  { value: "in_progress", label: "In Progress", color: "border-blue-400/30 bg-blue-400/10 text-blue-200 hover:border-blue-400/60" },
  { value: "done",        label: "Done",        color: "border-teal-400/30 bg-teal-400/10 text-teal-200 hover:border-teal-400/60" },
];

const STATUS_OPTS = [
  { value: "open",       label: "Open",       desc: "Newly created, not yet actioned" },
  { value: "active",     label: "Active",     desc: "Actively being investigated" },
  { value: "monitoring", label: "Monitoring", desc: "Under observation after initial triage" },
  { value: "resolved",   label: "Resolved",   desc: "Root cause identified and contained" },
  { value: "closed",     label: "Closed",     desc: "Fully concluded, no further action needed" },
];

const SEV_OPTS = [
  { value: "important",     label: "Important",     desc: "Immediate response required" },
  { value: "notable",       label: "Notable",       desc: "Significant finding, prioritise" },
  { value: "interesting",   label: "Interesting",   desc: "Moderate risk, scheduled review" },
  { value: "informational", label: "Informational", desc: "No immediate action required" },
];

export default function CaseDetailPage() {
  const { id }                = useParams<{ id: string }>();
  const [c, setC]             = useState<CaseDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [addInvId, setAddInvId]       = useState("");
  const [invSearch, setInvSearch]     = useState("");
  const [invOptions, setInvOptions]   = useState<InvOption[]>([]);
  const [invLoading, setInvLoading]   = useState(false);
  const [pickerOpen, setPickerOpen]   = useState(false);
  const [selectedInv, setSelectedInv] = useState<InvOption | null>(null);
  const [note, setNote]       = useState("");
  const [saving, setSaving]   = useState(false);

  // ── Tasks ────────────────────────────────────────────────────────────────
  const [tasks, setTasks]             = useState<CaseTask[]>([]);
  const [taskUsers, setTaskUsers]     = useState<TaskUser[]>([]);
  const [expandedTasks, setExpandedTasks] = useState<Set<string>>(new Set());
  const [findingCache, setFindingCache]   = useState<Record<string, RelatedFinding>>({});

  const [newTaskTitle, setNewTaskTitle]       = useState("");
  const [newTaskPriority, setNewTaskPriority] = useState<CaseTask["priority"]>("medium");
  const [newTaskDueAt, setNewTaskDueAt]       = useState("");
  const [newTaskOwnerId, setNewTaskOwnerId]   = useState("");
  const [addingTask, setAddingTask]           = useState(false);

  const [findingPickerTaskId, setFindingPickerTaskId] = useState<string | null>(null);
  const [findingSearch, setFindingSearch]             = useState("");
  const [findingResults, setFindingResults]           = useState<RelatedFinding[]>([]);
  const [findingSearchLoading, setFindingSearchLoading] = useState(false);

  useEffect(() => {
    if (!pickerOpen) return;
    setInvLoading(true);
    const q = invSearch.trim();
    fetch(`/api/investigations${q ? `?q=${encodeURIComponent(q)}` : ""}`)
      .then(r => r.ok ? r.json() : { investigations: [] })
      .then(d => setInvOptions(d.investigations ?? []))
      .finally(() => setInvLoading(false));
  }, [pickerOpen, invSearch]);

  async function loadTasks() {
    const res = await fetch(`/api/cases/${id}/tasks`);
    if (res.ok) setTasks((await res.json()).tasks ?? []);
  }

  useEffect(() => { if (id) loadTasks(); }, [id]);

  useEffect(() => {
    fetch("/api/users?limit=100")
      .then(r => r.ok ? r.json() : { users: [] })
      .then(d => setTaskUsers(d.users ?? []));
  }, []);

  function cacheFindings(list: RelatedFinding[]) {
    setFindingCache((prev) => {
      const next = { ...prev };
      for (const f of list) next[f.id] = f;
      return next;
    });
  }

  // Resolve display info for any linked finding ids not already cached
  useEffect(() => {
    const missing = Array.from(new Set(tasks.flatMap((t) => t.relatedFindingIds))).filter((fid) => !findingCache[fid]);
    if (missing.length === 0) return;
    fetch(`/api/cases/${id}/findings?ids=${missing.join(",")}`)
      .then((r) => r.ok ? r.json() : { findings: [] })
      .then((d) => cacheFindings(d.findings ?? []));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tasks]);

  useEffect(() => {
    if (!findingPickerTaskId) return;
    setFindingSearchLoading(true);
    const q = findingSearch.trim();
    fetch(`/api/cases/${id}/findings${q ? `?q=${encodeURIComponent(q)}` : ""}`)
      .then((r) => r.ok ? r.json() : { findings: [] })
      .then((d) => {
        setFindingResults(d.findings ?? []);
        cacheFindings(d.findings ?? []);
      })
      .finally(() => setFindingSearchLoading(false));
  }, [findingPickerTaskId, findingSearch, id]);

  async function createTask() {
    if (!newTaskTitle.trim()) return;
    setAddingTask(true);
    await fetch(`/api/cases/${id}/tasks`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        title: newTaskTitle.trim(),
        priority: newTaskPriority,
        ...(newTaskDueAt ? { dueAt: newTaskDueAt } : {}),
        ...(newTaskOwnerId ? { ownerId: newTaskOwnerId } : {}),
      }),
    });
    setNewTaskTitle(""); setNewTaskPriority("medium"); setNewTaskDueAt(""); setNewTaskOwnerId("");
    setAddingTask(false);
    loadTasks();
  }

  async function patchTask(taskId: string, data: Record<string, unknown>) {
    await fetch(`/api/cases/${id}/tasks/${taskId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(data),
    });
    loadTasks();
  }

  async function deleteTask(taskId: string) {
    await fetch(`/api/cases/${id}/tasks/${taskId}`, { method: "DELETE" });
    loadTasks();
  }

  function toggleTaskDone(task: CaseTask) {
    patchTask(task.id, { status: task.status === "done" ? "todo" : "done" });
  }

  function toggleExpand(taskId: string) {
    setExpandedTasks((prev) => {
      const next = new Set(prev);
      if (next.has(taskId)) next.delete(taskId); else next.add(taskId);
      return next;
    });
  }

  function linkFinding(task: CaseTask, findingId: string) {
    if (task.relatedFindingIds.includes(findingId)) return;
    patchTask(task.id, { relatedFindingIds: [...task.relatedFindingIds, findingId] });
  }

  function unlinkFinding(task: CaseTask, findingId: string) {
    patchTask(task.id, { relatedFindingIds: task.relatedFindingIds.filter((fid) => fid !== findingId) });
  }

  async function load() {
    setLoading(true);
    const res = await fetch(`/api/cases/${id}`);
    if (res.ok) setC((await res.json()).case);
    setLoading(false);
  }

  // Silent background refresh — keeps the stats box (investigations/log/pcap/
  // ram counts) current if something's uploaded against this case elsewhere,
  // without flashing the whole page back to its loading state.
  async function loadSilently() {
    const res = await fetch(`/api/cases/${id}`);
    if (res.ok) setC((await res.json()).case);
  }

  useEffect(() => { if (id) load(); }, [id]);

  useEffect(() => {
    if (!id) return;
    const interval = setInterval(loadSilently, 15_000);
    return () => clearInterval(interval);
  }, [id]);

  async function patch(data: Record<string, unknown>) {
    await fetch(`/api/cases/${id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(data),
    });
    load();
  }

  async function linkInvestigation() {
    if (!addInvId.trim()) return;
    setSaving(true);
    await fetch(`/api/cases/${id}/investigations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ investigationId: addInvId.trim() }),
    });
    setAddInvId("");
    setSelectedInv(null);
    setPickerOpen(false);
    setInvSearch("");
    setSaving(false);
    load();
  }

  async function unlinkInvestigation(investigationId: string) {
    await fetch(`/api/cases/${id}/investigations`, {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ investigationId }),
    });
    load();
  }

  async function addNote() {
    if (!note.trim()) return;
    setSaving(true);
    await fetch(`/api/cases/${id}/notes`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ content: note.trim() }),
    });
    setNote("");
    setSaving(false);
    load();
  }

  if (loading) return <div className="p-8 text-zinc-500">Loading…</div>;
  if (!c)      return <div className="p-8 text-red-400">Case not found.</div>;

  // Closed cases stop accepting new evidence/reassignment — reopen via the
  // Status selector above to unlock these again. Notes/Tasks/Reports stay open.
  const isClosed = c.status === "closed";

  return (
    <div className="p-6 max-w-5xl mx-auto">
      {/* Breadcrumb */}
      <Link href="/cases" className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300 mb-4">
        <ArrowLeft className="h-4 w-4" /> Cases
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-6">
        <div className="flex-1 min-w-0">
          <p className="text-xs font-mono text-zinc-500 mb-0.5">{formatCaseNumber(c.caseSeq)}</p>
          <h1 className="text-2xl font-bold text-zinc-100 break-words">{c.title}</h1>
          {c.description && <p className="mt-1 text-sm text-zinc-400">{c.description}</p>}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {/* Status selector — changes the case workflow status */}
          <label className="text-xs text-zinc-500 hidden sm:block">Status:</label>
          <select
            value={c.status}
            onChange={(e) => patch({ status: e.target.value })}
            title={STATUS_OPTS.find(o => o.value === c.status)?.desc ?? c.status}
            className="rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-200"
          >
            {STATUS_OPTS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
          {/* Priority/Severity selector — sets the case risk level */}
          <label className="text-xs text-zinc-500 hidden sm:block">Priority:</label>
          <select
            value={c.severity}
            onChange={(e) => patch({ severity: e.target.value })}
            title={SEV_OPTS.find(o => o.value === c.severity)?.desc ?? c.severity}
            className="rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-200"
          >
            {SEV_OPTS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
          <button onClick={load} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-300">
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Case stats — always reflects what's currently linked to this case; refresh (above) or reload the page to pick up anything added elsewhere */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        {[
          { label: "Investigations", value: c.investigations.length,  icon: Link2,       color: "text-teal-400" },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 text-center">
            <Icon className={`h-5 w-5 mx-auto mb-2 ${color}`} />
            <div className={`text-xl font-bold ${color}`}>{value}</div>
            <div className="text-xs text-zinc-500 mt-1">{label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left — Investigations */}
        <div className="lg:col-span-2 space-y-6">
          {/* Investigations */}
          <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <h2 className="text-sm font-semibold text-zinc-300 mb-3 flex items-center gap-2">
              <Link2 className="h-4 w-4 text-zinc-500" /> Investigations ({c.investigations.length})
            </h2>
            {c.investigations.length === 0 ? (
              <p className="text-sm text-zinc-600">No investigations linked yet.</p>
            ) : (
              <div className="space-y-2">
                {c.investigations.map((inv) => (
                  <div key={inv.id} className="flex items-center justify-between rounded-lg border border-zinc-800 px-3 py-2">
                    <Link href={`/investigations/${inv.id}`} className="text-sm font-medium text-teal-400 hover:text-teal-300">
                      {inv.hostname ?? inv.title}
                    </Link>
                    <div className="flex items-center gap-3 text-xs text-zinc-500">
                      <span>{inv.status}</span>
                      <span>{inv.findingCount} finding{inv.findingCount !== 1 ? "s" : ""}</span>
                      {!isClosed && (
                        <button onClick={() => unlinkInvestigation(inv.id)} className="text-zinc-600 hover:text-red-400">
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
            {/* Investigation picker */}
            {isClosed ? (
              <p className="mt-3 text-xs text-zinc-600 rounded-md border border-dashed border-zinc-800 px-3 py-2">
                This case is closed — reopen it (Status selector above) to link or unlink investigations.
              </p>
            ) : (
            <div className="mt-3 space-y-2">
              {!pickerOpen ? (
                <button
                  onClick={() => setPickerOpen(true)}
                  className="flex items-center gap-1.5 rounded-md border border-dashed border-zinc-700 px-3 py-2 text-sm text-zinc-400 hover:border-teal-600 hover:text-teal-400 w-full transition-colors"
                >
                  <Link2 className="h-3.5 w-3.5" /> Link an investigation…
                </button>
              ) : (
                <div className="rounded-lg border border-zinc-700 bg-zinc-950 overflow-hidden">
                  {/* Search input */}
                  <div className="flex items-center gap-2 px-3 py-2 border-b border-zinc-800">
                    <Search className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
                    <input
                      autoFocus
                      value={invSearch}
                      onChange={e => setInvSearch(e.target.value)}
                      placeholder="Search by hostname or title…"
                      className="flex-1 bg-transparent text-sm text-zinc-200 placeholder-zinc-600 outline-none"
                    />
                    <button onClick={() => { setPickerOpen(false); setInvSearch(""); setSelectedInv(null); setAddInvId(""); }} className="text-zinc-600 hover:text-zinc-300">&times;</button>
                  </div>

                  {/* Results — an investigation can only belong to one case,
                      so only unassigned ones are offered here. */}
                  <div className="max-h-52 overflow-y-auto">
                    {invLoading ? (
                      <p className="px-3 py-4 text-xs text-zinc-600 text-center">Loading…</p>
                    ) : invOptions.filter(inv => !inv.caseId).length === 0 ? (
                      <p className="px-3 py-4 text-xs text-zinc-600 text-center">No unassigned investigations found.</p>
                    ) : (
                      invOptions
                        .filter(inv => !inv.caseId)
                        .map(inv => (
                          <button
                            key={inv.id}
                            onClick={() => { setSelectedInv(inv); setAddInvId(inv.id); }}
                            className={`w-full flex items-center justify-between px-3 py-2.5 text-left hover:bg-zinc-800 transition-colors border-b border-zinc-800/50 last:border-0 ${
                              selectedInv?.id === inv.id ? "bg-teal-900/20" : ""
                            }`}
                          >
                            <div className="min-w-0">
                              <p className="text-sm font-medium text-zinc-200 truncate">{inv.title ?? inv.hostname ?? inv.id}</p>
                              {inv.title && inv.hostname && inv.title !== inv.hostname && (
                                <p className="text-xs text-zinc-500 truncate">{inv.hostname}</p>
                              )}
                            </div>
                            <div className="flex items-center gap-2 shrink-0 ml-3 text-xs text-zinc-500">
                              <span>{inv.findingCount} findings</span>
                              <span>{new Date(inv.createdAt).toLocaleDateString()}</span>
                              {selectedInv?.id === inv.id && <span className="text-teal-400 font-medium">✓</span>}
                            </div>
                          </button>
                        ))
                    )}
                  </div>

                  {/* Selected + confirm */}
                  {selectedInv && (
                    <div className="flex items-center justify-between gap-2 px-3 py-2 border-t border-zinc-800 bg-zinc-900">
                      <p className="text-xs text-zinc-400 truncate">
                        Selected: <span className="text-teal-400 font-medium">{selectedInv.title ?? selectedInv.hostname}</span>
                      </p>
                      <button
                        onClick={linkInvestigation}
                        disabled={saving}
                        className="shrink-0 rounded-md bg-teal-600 px-3 py-1 text-xs font-medium text-white hover:bg-teal-500 disabled:opacity-50"
                      >
                        {saving ? "Linking…" : "Link"}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
            )}
          </section>

          {/* Tasks */}
          <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <h2 className="text-sm font-semibold text-zinc-300 mb-3 flex items-center gap-2">
              <ListChecks className="h-4 w-4 text-zinc-500" /> Tasks ({tasks.length})
            </h2>

            {tasks.length === 0 ? (
              <p className="text-sm text-zinc-600 mb-3">No tasks yet. Add investigator actions below.</p>
            ) : (
              <div className="space-y-2 mb-3">
                {tasks.map((task) => {
                  const isExpanded = expandedTasks.has(task.id);
                  const overdue = task.dueAt && task.status !== "done" && new Date(task.dueAt) < new Date();
                  return (
                    <div key={task.id} className="rounded-lg border border-zinc-800 px-3 py-2">
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={task.status === "done"}
                          onChange={() => toggleTaskDone(task)}
                          className="shrink-0 accent-teal-500"
                        />
                        <button
                          onClick={() => toggleExpand(task.id)}
                          className={`flex-1 min-w-0 text-left text-sm ${task.status === "done" ? "text-zinc-600 line-through" : "text-zinc-200"}`}
                        >
                          {task.title}
                        </button>
                        <span className={`text-xs font-medium shrink-0 ${TASK_PRIORITY_COLOR[task.priority]}`}>{task.priority}</span>
                        {task.dueAt && (
                          <span className={`text-xs shrink-0 ${overdue ? "text-red-400 font-medium" : "text-zinc-500"}`}>
                            {new Date(task.dueAt).toLocaleDateString()}
                          </span>
                        )}
                        <select
                          value={task.owner?.id ?? ""}
                          onChange={(e) => patchTask(task.id, { ownerId: e.target.value || null })}
                          className="shrink-0 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-300 max-w-[110px]"
                        >
                          <option value="">Unassigned</option>
                          {taskUsers.map((u) => (
                            <option key={u.id} value={u.id}>{u.name ?? u.email}</option>
                          ))}
                        </select>
                        <button onClick={() => toggleExpand(task.id)} className="shrink-0 text-zinc-600 hover:text-zinc-300">
                          {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                        </button>
                        <button onClick={() => deleteTask(task.id)} className="shrink-0 text-zinc-600 hover:text-red-400">
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>

                      {isExpanded && (
                        <div className="mt-3 pt-3 border-t border-zinc-800 space-y-3">
                          {/* Status */}
                          <div className="flex flex-wrap gap-1.5">
                            {TASK_STATUS_OPTS.map((opt) => (
                              <button
                                key={opt.value}
                                onClick={() => patchTask(task.id, { status: opt.value })}
                                className={`rounded border px-2.5 py-1 text-xs font-medium transition-all ${opt.color} ${task.status === opt.value ? "ring-1 ring-offset-1 ring-offset-zinc-950" : "opacity-70"}`}
                              >
                                {opt.label}
                              </button>
                            ))}
                          </div>

                          {/* Notes */}
                          <textarea
                            defaultValue={task.notes ?? ""}
                            onBlur={(e) => { if (e.target.value !== (task.notes ?? "")) patchTask(task.id, { notes: e.target.value }); }}
                            placeholder="Notes…"
                            rows={2}
                            className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500 resize-none"
                          />

                          {/* Related findings */}
                          <div>
                            <p className="text-xs font-medium text-zinc-500 mb-1.5">Related Findings</p>
                            <div className="flex flex-wrap gap-1.5 mb-1.5">
                              {task.relatedFindingIds.map((fid) => {
                                const f = findingCache[fid];
                                return (
                                  <span key={fid} className="inline-flex items-center gap-1 rounded-full border border-zinc-700 bg-zinc-950 px-2 py-0.5 text-xs text-zinc-300">
                                    {f ? (
                                      <Link href={`/investigations/${f.investigation.id}`} className="hover:text-teal-400">
                                        {f.findingType} · {f.investigation.hostname ?? "—"}
                                      </Link>
                                    ) : (
                                      <span className="text-zinc-600">{fid.slice(0, 8)}</span>
                                    )}
                                    <button onClick={() => unlinkFinding(task, fid)} className="text-zinc-600 hover:text-red-400">
                                      <X className="h-3 w-3" />
                                    </button>
                                  </span>
                                );
                              })}
                            </div>

                            {findingPickerTaskId === task.id ? (
                              <div className="rounded-lg border border-zinc-700 bg-zinc-950 overflow-hidden">
                                <div className="flex items-center gap-2 px-3 py-2 border-b border-zinc-800">
                                  <Search className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
                                  <input
                                    autoFocus
                                    value={findingSearch}
                                    onChange={(e) => setFindingSearch(e.target.value)}
                                    placeholder="Search findings…"
                                    className="flex-1 bg-transparent text-sm text-zinc-200 placeholder-zinc-600 outline-none"
                                  />
                                  <button onClick={() => { setFindingPickerTaskId(null); setFindingSearch(""); }} className="text-zinc-600 hover:text-zinc-300">
                                    <X className="h-3.5 w-3.5" />
                                  </button>
                                </div>
                                <div className="max-h-40 overflow-y-auto">
                                  {findingSearchLoading ? (
                                    <p className="px-3 py-3 text-xs text-zinc-600 text-center">Loading…</p>
                                  ) : findingResults.length === 0 ? (
                                    <p className="px-3 py-3 text-xs text-zinc-600 text-center">No findings found.</p>
                                  ) : (
                                    findingResults
                                      .filter((f) => !task.relatedFindingIds.includes(f.id))
                                      .map((f) => (
                                        <button
                                          key={f.id}
                                          onClick={() => linkFinding(task, f.id)}
                                          className="w-full flex items-center justify-between px-3 py-2 text-left hover:bg-zinc-800 border-b border-zinc-800/50 last:border-0"
                                        >
                                          <span className="text-sm text-zinc-200 truncate">{f.findingType} · {f.category}</span>
                                          <span className="text-xs text-zinc-500 shrink-0 ml-2">{f.investigation.hostname ?? "—"}</span>
                                        </button>
                                      ))
                                  )}
                                </div>
                              </div>
                            ) : (
                              <button
                                onClick={() => setFindingPickerTaskId(task.id)}
                                className="text-xs text-teal-500 hover:text-teal-300"
                              >
                                + Link a finding…
                              </button>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* Add-task inline form */}
            <div className="flex flex-wrap gap-2">
              <input
                value={newTaskTitle}
                onChange={(e) => setNewTaskTitle(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && createTask()}
                placeholder="Add task…"
                className="flex-1 min-w-[160px] rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
              />
              <select
                value={newTaskPriority}
                onChange={(e) => setNewTaskPriority(e.target.value as CaseTask["priority"])}
                className="rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-xs text-zinc-300"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <input
                type="date"
                value={newTaskDueAt}
                onChange={(e) => setNewTaskDueAt(e.target.value)}
                className="rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-xs text-zinc-300"
              />
              <select
                value={newTaskOwnerId}
                onChange={(e) => setNewTaskOwnerId(e.target.value)}
                className="rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-xs text-zinc-300 max-w-[130px]"
              >
                <option value="">Unassigned</option>
                {taskUsers.map((u) => (
                  <option key={u.id} value={u.id}>{u.name ?? u.email}</option>
                ))}
              </select>
              <button
                onClick={createTask}
                disabled={addingTask || !newTaskTitle.trim()}
                className="inline-flex items-center gap-1 rounded-md bg-teal-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50"
              >
                <Plus className="h-3.5 w-3.5" /> Add
              </button>
            </div>
          </section>

          {/* Reports */}
          <ReportGenerator caseId={c.id} />

          {/* Threat Intel */}
          <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <CaseThreatIntelSection caseId={c.id} />
          </section>
        </div>

        {/* Right — Notes + Meta */}
        <div className="space-y-6">
          {/* Assignee */}
          <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <AssigneePanel
              assigneeId={c.assignee?.id ?? null}
              onAssign={(userId) => patch({ assigneeId: userId })}
              disabled={isClosed}
              disabledReason="This case is closed — reopen it (Status selector above) to change the assignee."
            />
          </section>

          {/* Meta */}
          <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 text-sm space-y-2">
            <h2 className="font-semibold text-zinc-300 mb-2">Details</h2>
            <div className="flex justify-between text-zinc-500">
              <span>Created</span>
              <span>{new Date(c.createdAt).toLocaleDateString()}</span>
            </div>
            <div className="flex justify-between text-zinc-500">
              <span>Updated</span>
              <span>{new Date(c.updatedAt).toLocaleDateString()}</span>
            </div>
            <div className="flex justify-between text-zinc-500">
              <span>Created by</span>
              <span>{c.createdBy?.name ?? c.createdBy?.email ?? "—"}</span>
            </div>
          </section>

          {/* Notes */}
          <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <h2 className="text-sm font-semibold text-zinc-300 mb-3">Notes ({c.notes.length})</h2>
            <div className="space-y-2 max-h-60 overflow-y-auto mb-3">
              {c.notes.map((n) => (
                <div key={n.id} className="rounded-lg bg-zinc-800 px-3 py-2 text-sm">
                  <p className="text-zinc-200 text-xs">{n.content}</p>
                  <p className="text-zinc-600 text-xs mt-1">{n.author.name ?? n.author.email} · {new Date(n.createdAt).toLocaleDateString()}</p>
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && addNote()}
                placeholder="Add note…"
                className="flex-1 rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
              />
              <button
                onClick={addNote}
                disabled={saving || !note.trim()}
                className="rounded-md bg-zinc-700 px-3 py-1.5 text-sm font-medium text-zinc-200 hover:bg-zinc-600 disabled:opacity-50"
              >
                Add
              </button>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
