"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Archive, ArchiveRestore } from "lucide-react";
import type { ArchiveType } from "@/lib/cases/archive";

const CONFIRM: Record<"archive" | "restore", string> = {
  archive: "Archive this? It leaves the working lists, dashboard and search (it stays in host profiles and on the Archive page) and stays read-only until restored.",
  restore: "Restore this from the archive? It returns to the working lists.",
};

/**
 * Archive or restore one case/investigation/upload via POST /api/archive.
 * The server enforces the rules (only closed cases; investigations/uploads
 * only when they belong to no case) and its message is shown on refusal.
 */
export function ArchiveButton({
  type, id, action, onDone, compact = false,
}: {
  type: ArchiveType;
  id: string;
  action: "archive" | "restore";
  onDone?: () => void;
  compact?: boolean;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function run() {
    if (!window.confirm(CONFIRM[action])) return;
    setBusy(true);
    const res = await fetch("/api/archive", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type, id, action }),
    });
    setBusy(false);
    if (!res.ok) {
      window.alert((await res.json().catch(() => ({}))).error ?? "Couldn't update the archive.");
      return;
    }
    if (onDone) onDone(); else router.refresh();
  }

  const Icon = action === "archive" ? Archive : ArchiveRestore;
  const label = action === "archive" ? "Archive" : "Restore";
  return compact ? (
    <button onClick={run} disabled={busy} title={label} className="p-1.5 rounded text-zinc-600 hover:text-zinc-200 hover:bg-zinc-800 disabled:opacity-50">
      <Icon className="h-3.5 w-3.5" />
    </button>
  ) : (
    <button
      onClick={run}
      disabled={busy}
      className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:border-zinc-500 hover:text-zinc-100 disabled:opacity-50"
    >
      <Icon className="h-3.5 w-3.5" /> {busy ? "Working…" : label}
    </button>
  );
}

export function ArchivedPill() {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full border border-zinc-600 bg-zinc-800 px-2 py-0.5 text-xs font-medium text-zinc-300"
      title="Archived — read-only, and hidden from the working lists until restored from the Archive page."
    >
      <Archive className="h-3 w-3" /> Archived
    </span>
  );
}
