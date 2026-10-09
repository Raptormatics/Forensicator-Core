"use client";

import { useState, useEffect } from "react";
import { normalizeSeverity, severityClassName, SEVERITY_LABELS } from "@/lib/severity";

type Props = { findingId: string; severity: string; onChanged?: (severity: string) => void };

/** Clickable SeverityBadge — opens a small menu to manually override/escalate a finding's severity. */
export function SeverityOverrideBadge({ findingId, severity, onChanged }: Props) {
  const [current, setCurrent] = useState(severity);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, [open]);

  async function setSeverity(next: string) {
    setOpen(false);
    if (next === normalizeSeverity(current)) return;
    setSaving(true);
    try {
      const res = await fetch(`/api/findings/${findingId}/severity`, {
        method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ severity: next }),
      });
      if (res.ok) {
        setCurrent(next);
        onChanged?.(next);
      }
    } finally {
      setSaving(false);
    }
  }

  return (
    <span className="relative inline-block">
      <button
        onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
        disabled={saving}
        title="Click to override severity"
        className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${severityClassName(current)} hover:brightness-125 disabled:opacity-50`}
      >
        {normalizeSeverity(current)}
      </button>
      {open && (
        <div
          onClick={(e) => e.stopPropagation()}
          className="absolute left-0 top-full z-20 mt-1 w-40 rounded-lg border border-zinc-700 bg-zinc-950 shadow-xl overflow-hidden py-1"
        >
          {SEVERITY_LABELS.map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(s)}
              className={`w-full text-left px-3 py-1.5 text-xs hover:bg-zinc-800 ${normalizeSeverity(current) === s ? "text-teal-400 font-medium" : "text-zinc-300"}`}
            >
              {s}
            </button>
          ))}
        </div>
      )}
    </span>
  );
}
