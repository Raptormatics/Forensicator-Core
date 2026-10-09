"use client";

import { useState } from "react";
import { Radar } from "lucide-react";

type EnrichResult = {
  evidenceScanned: number;
  uniqueIocs: number;
  newRecords: number;
  feedMatches: number;
  queued: number;
  truncated: boolean;
};

type Props = {
  investigationId: string;
  /** Empty/undefined enriches every artifact type in the investigation ("All" tab). */
  type?: string;
};

export function ArtifactTypeEnrichButton({ investigationId, type }: Props) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch(`/api/investigations/${investigationId}/artifacts/enrich`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(type ? { type } : {}),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data) {
        setMsg("Enrichment failed — please retry.");
        return;
      }
      const r = data as EnrichResult;
      if (r.uniqueIocs === 0) {
        setMsg(`Scanned ${r.evidenceScanned.toLocaleString()} rows — no usable indicators found.`);
        return;
      }
      setMsg(
        `Scanned ${r.evidenceScanned.toLocaleString()} row${r.evidenceScanned !== 1 ? "s" : ""}, ` +
        `found ${r.uniqueIocs.toLocaleString()} indicator${r.uniqueIocs !== 1 ? "s" : ""} ` +
        `(${r.newRecords} new). ${r.feedMatches} matched the local URLhaus feed, ${r.queued} queued for live lookup.` +
        (r.truncated ? " (Scan capped — run again to continue.)" : "")
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
        title="Extract indicators from this artifact type's evidence and queue them for threat-intel enrichment"
        className="inline-flex items-center gap-1.5 rounded border border-teal-800 bg-teal-950/40 px-3 py-1.5 text-xs font-medium text-teal-300 hover:bg-teal-900/50 disabled:opacity-50"
      >
        <Radar className="h-3.5 w-3.5" />
        {busy ? "Enriching…" : type ? `Enrich ${type}` : "Enrich All Artifacts"}
      </button>
      {msg && <span className="text-xs text-zinc-500">{msg}</span>}
    </div>
  );
}
