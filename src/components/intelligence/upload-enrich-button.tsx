"use client";

import { useState } from "react";
import { Radar } from "lucide-react";

type EnrichResult = {
  uniqueIocs: number;
  newRecords: number;
  feedMatches: number;
  queued: number;
  truncated: boolean;
};

type Props = { endpoint: string };

export function UploadEnrichButton({ endpoint }: Props) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch(endpoint, { method: "POST" });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data) {
        setMsg("Enrichment failed — please retry.");
        return;
      }
      const r = data as EnrichResult;
      if (r.uniqueIocs === 0) {
        setMsg("No enrichable indicators found for this upload.");
        return;
      }
      setMsg(
        `${r.uniqueIocs.toLocaleString()} indicator${r.uniqueIocs !== 1 ? "s" : ""} checked ` +
        `(${r.newRecords} new). ${r.feedMatches} matched the local URLhaus feed, ${r.queued} queued for live lookup.` +
        (r.truncated ? " (Live-lookup queue hit this run's cap — run again to continue.)" : "")
      );
    } catch {
      setMsg("Enrichment failed — network error.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        onClick={run}
        disabled={busy}
        title="Check every extracted indicator from this upload against threat intel — including ones seen before that were never actually enriched"
        className="inline-flex items-center gap-1.5 rounded-md border border-teal-800 bg-teal-950/40 px-3 py-1.5 text-xs font-medium text-teal-300 hover:bg-teal-900/50 disabled:opacity-50"
      >
        <Radar className="h-3.5 w-3.5" /> {busy ? "Enriching…" : "Enrich IOCs"}
      </button>
      {msg && <span className="text-xs text-zinc-500">{msg}</span>}
    </div>
  );
}
