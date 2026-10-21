"use client";

import { useState } from "react";
import { Lock, LockOpen, X } from "lucide-react";

export const DISPOSITION_OPTS = [
  { value: "true_positive",  label: "True positive",  desc: "Confirmed malicious activity / incident" },
  { value: "false_positive", label: "False positive", desc: "Detection fired, but nothing malicious happened" },
  { value: "benign",         label: "Benign",         desc: "Real activity, but authorized or expected" },
  { value: "inconclusive",   label: "Inconclusive",   desc: "Not enough evidence to decide either way" },
] as const;

export function dispositionLabel(value: string | null | undefined): string {
  return DISPOSITION_OPTS.find((d) => d.value === value)?.label ?? value ?? "—";
}

const PENDING_LABELS: Record<string, string> = {
  logUploads: "log uploads", pcapUploads: "PCAP uploads", ramUploads: "RAM uploads",
  ramSessions: "RAM transfers", windowsArtifactFiles: "Windows artifact files", aiAnalyses: "AI analyses",
};

/**
 * Close or reopen a case. Closing records a disposition and summary and
 * freezes everything linked to the case; reopening needs a reason. Both are
 * written to the audit log by PATCH /api/cases/[id].
 */
export function CaseClosureDialog({
  caseId, mode, reopenStatus, onClose, onDone,
}: {
  caseId: string;
  mode: "close" | "reopen";
  reopenStatus?: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [disposition, setDisposition] = useState<string>("");
  const [text, setText] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid = mode === "close" ? !!disposition && text.trim().length > 0 : text.trim().length >= 10;

  async function submit() {
    setSaving(true);
    setError(null);
    const body = mode === "close"
      ? { status: "closed", closureDisposition: disposition, closureSummary: text.trim() }
      : { status: reopenStatus ?? "active", reopenReason: text.trim() };
    const res = await fetch(`/api/cases/${caseId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    setSaving(false);
    if (res.ok) { onDone(); return; }
    const data = await res.json().catch(() => ({}));
    const pending = data.pending as Record<string, number> | undefined;
    const detail = pending
      ? Object.entries(pending).filter(([, n]) => n > 0).map(([k, n]) => `${PENDING_LABELS[k] ?? k}: ${n}`).join(", ")
      : "";
    setError(`${data.error ?? "Couldn't update the case."}${detail ? ` (${detail})` : ""}`);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-lg rounded-xl border border-zinc-800 bg-zinc-900 p-5" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-3">
          <h2 className="text-base font-semibold text-zinc-100 flex items-center gap-2">
            {mode === "close" ? <Lock className="h-4 w-4 text-amber-400" /> : <LockOpen className="h-4 w-4 text-teal-400" />}
            {mode === "close" ? "Close case" : "Reopen case"}
          </h2>
          <button onClick={onClose} className="text-zinc-600 hover:text-zinc-300"><X className="h-4 w-4" /></button>
        </div>

        {mode === "close" ? (
          <>
            <p className="text-xs text-zinc-400 mb-4">
              Closing freezes this case: its investigations and uploads can&apos;t be unlinked, moved to another case or deleted,
              and findings, notes and tasks become read-only. You can still view, export and generate reports.
              Reopening later needs a reason, and both are recorded in the audit log.
            </p>
            <p className="text-xs font-medium text-zinc-400 mb-1.5">Disposition</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-4">
              {DISPOSITION_OPTS.map((d) => (
                <button
                  key={d.value}
                  onClick={() => setDisposition(d.value)}
                  className={`rounded-md border px-3 py-2 text-left transition-colors ${
                    disposition === d.value ? "border-teal-500 bg-teal-900/20" : "border-zinc-800 hover:border-zinc-600"
                  }`}
                >
                  <p className="text-sm text-zinc-200">{d.label}</p>
                  <p className="text-xs text-zinc-500">{d.desc}</p>
                </button>
              ))}
            </div>
            <p className="text-xs font-medium text-zinc-400 mb-1.5">Closure summary</p>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={4}
              placeholder="What happened, what was done about it, and why the case can be closed…"
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500 resize-none"
            />
          </>
        ) : (
          <>
            <p className="text-xs text-zinc-400 mb-4">
              Reopening unfreezes this case and everything linked to it. The reason is recorded in the audit log alongside the original closure.
            </p>
            <p className="text-xs font-medium text-zinc-400 mb-1.5">Reason for reopening</p>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={3}
              placeholder="e.g. New activity seen on the same host…"
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500 resize-none"
            />
            <p className="text-xs text-zinc-600 mt-1">At least 10 characters.</p>
          </>
        )}

        {error && <p className="mt-3 rounded px-2 py-1.5 text-xs bg-red-900/30 text-red-400">{error}</p>}

        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:border-zinc-500">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={!valid || saving}
            className={`rounded-md px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50 ${
              mode === "close" ? "bg-amber-600 hover:bg-amber-500" : "bg-teal-600 hover:bg-teal-500"
            }`}
          >
            {saving ? "Saving…" : mode === "close" ? "Close case" : "Reopen case"}
          </button>
        </div>
      </div>
    </div>
  );
}
