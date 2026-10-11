"use client";

import { useEffect, useState } from "react";
import { X } from "lucide-react";

type TaskUser = { id: string; email: string; name: string | null };
type CaseOption = { id: string; title: string; caseSeq: number };
type Priority = "critical" | "high" | "medium" | "low";

export type QuickTaskDetails = {
  caseId: string;
  title: string;
  notes: string;
  priority: Priority;
  dueAt: string;
  ownerId: string;
};

type Props = {
  heading: string;
  defaultTitle: string;
  defaultNotes?: string;
  defaultPriority?: Priority;
  cases: CaseOption[];
  onClose: () => void;
  onSubmit: (details: QuickTaskDetails) => Promise<void>;
};

function formatCaseNumber(seq: number): string {
  return `CASE-${String(seq).padStart(4, "0")}`;
}

export function QuickTaskModal({ heading, defaultTitle, defaultNotes, defaultPriority, cases, onClose, onSubmit }: Props) {
  const [title, setTitle] = useState(defaultTitle);
  const [notes, setNotes] = useState(defaultNotes ?? "");
  const [priority, setPriority] = useState<Priority>(defaultPriority ?? "high");
  const [dueAt, setDueAt] = useState("");
  const [ownerId, setOwnerId] = useState("");
  const [caseId, setCaseId] = useState(cases[0]?.id ?? "");
  const [users, setUsers] = useState<TaskUser[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/users?limit=100")
      .then((r) => (r.ok ? r.json() : { users: [] }))
      .then((d) => setUsers(d.users ?? []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function submit() {
    if (!title.trim()) { setError("Task title is required."); return; }
    if (!caseId) { setError("No case is linked to this indicator — a task must belong to a case."); return; }
    setSubmitting(true);
    setError(null);
    try {
      await onSubmit({ caseId, title: title.trim(), notes: notes.trim(), priority, dueAt, ownerId });
    } catch {
      setError("Failed to create task — please retry.");
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={onClose}>
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg rounded-lg border border-zinc-700 bg-zinc-950 shadow-2xl"
      >
        <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
          <h3 className="text-sm font-semibold text-zinc-100">{heading}</h3>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-3 p-4">
          {cases.length > 1 && (
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Case</label>
              <select
                value={caseId}
                onChange={(e) => setCaseId(e.target.value)}
                className="w-full rounded border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-sm text-zinc-200"
              >
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>{formatCaseNumber(c.caseSeq)} — {c.title}</option>
                ))}
              </select>
            </div>
          )}
          {cases.length === 1 && (
            <p className="text-xs text-zinc-500">
              Task will be added to <span className="text-zinc-300">{formatCaseNumber(cases[0].caseSeq)} — {cases[0].title}</span>
            </p>
          )}

          <div>
            <label className="mb-1 block text-xs text-zinc-500">Task title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full rounded border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-sm text-zinc-200"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs text-zinc-500">Notes</label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              className="w-full resize-none rounded border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-sm text-zinc-200"
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Priority</label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as Priority)}
                className="w-full rounded border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-sm text-zinc-200"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Due date</label>
              <input
                type="date"
                value={dueAt}
                onChange={(e) => setDueAt(e.target.value)}
                className="w-full rounded border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-sm text-zinc-200"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Assignee</label>
              <select
                value={ownerId}
                onChange={(e) => setOwnerId(e.target.value)}
                className="w-full rounded border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-sm text-zinc-200"
              >
                <option value="">Unassigned</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>{u.name ?? u.email}</option>
                ))}
              </select>
            </div>
          </div>

          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>

        <div className="flex justify-end gap-2 border-t border-zinc-800 px-4 py-3">
          <button onClick={onClose} className="rounded border border-zinc-700 px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-200">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={submitting}
            className="rounded bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-500 disabled:opacity-50"
          >
            {submitting ? "Creating…" : "Create Task"}
          </button>
        </div>
      </div>
    </div>
  );
}
