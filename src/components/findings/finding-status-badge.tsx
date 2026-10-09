"use client";

import { useState } from "react";
import { ChevronDown } from "lucide-react";

const STATUSES = [
  { value: "new",            label: "New",            color: "text-zinc-300"  },
  { value: "under_review",   label: "Under Review",   color: "text-blue-400"  },
  { value: "confirmed",      label: "Confirmed",      color: "text-red-400"   },
  { value: "false_positive", label: "False Positive", color: "text-zinc-500"  },
  { value: "escalated",      label: "Escalated",      color: "text-orange-400"},
  { value: "resolved",       label: "Resolved",       color: "text-green-400" },
] as const;

type Status = (typeof STATUSES)[number]["value"];

export function FindingStatusBadge({
  findingId,
  initialStatus,
}: {
  findingId: string;
  initialStatus: Status;
}) {
  const [current, setCurrent] = useState<Status>(initialStatus);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);

  const info = STATUSES.find((s) => s.value === current) ?? STATUSES[0];

  async function set(newStatus: Status) {
    setOpen(false);
    if (newStatus === current) return;
    setSaving(true);
    try {
      await fetch(`/api/findings/${findingId}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      setCurrent(newStatus);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="relative inline-block text-left">
      <button
        className={`inline-flex items-center gap-1 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs font-medium transition-colors hover:border-zinc-600 disabled:opacity-50 ${info.color}`}
        onClick={() => setOpen((o) => !o)}
        disabled={saving}
      >
        {saving ? "Saving…" : info.label}
        <ChevronDown className="h-3 w-3 text-zinc-500" />
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute left-0 top-full z-20 mt-1 w-40 rounded-lg border border-zinc-700 bg-zinc-900 py-1 shadow-xl">
            {STATUSES.map((s) => (
              <button
                key={s.value}
                onClick={() => set(s.value)}
                className={`flex w-full items-center px-3 py-1.5 text-xs hover:bg-zinc-800 ${s.color} ${s.value === current ? "font-semibold" : ""}`}
              >
                {s.label}
                {s.value === current && <span className="ml-auto text-teal-400">✓</span>}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
