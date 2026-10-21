"use client";

import { RefreshCw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

export function BackfillButton({ investigationId }: { investigationId: string }) {
  const router = useRouter();
  const [state, setState] = useState<"idle" | "running" | "done" | "error">("idle");
  const [result, setResult] = useState<string | null>(null);

  async function run() {
    setState("running");
    setResult(null);
    try {
      const res = await fetch(`/api/investigations/${investigationId}/backfill`, {
        method: "POST",
      });
      const json = await res.json();
      if (res.ok) {
        setResult(
          `Extracted ${json.evidence_rows.toLocaleString()} evidence rows and ${json.timeline_events.toLocaleString()} timeline events from ${json.findings_processed} findings.`
        );
        setState("done");
        router.refresh();
      } else {
        setResult(json.message ?? json.error ?? "Backfill failed.");
        setState("error");
      }
    } catch (e) {
      setResult(e instanceof Error ? e.message : "Unexpected error.");
      setState("error");
    }
  }

  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900 p-4">
      <p className="text-sm text-zinc-300">
        No evidence rows found. This investigation was uploaded before evidence extraction was enabled, or the
        database migration hasn&apos;t run yet.
      </p>
      <div className="mt-3 flex items-center gap-3">
        <button
          onClick={run}
          disabled={state === "running" || state === "done"}
          className="inline-flex items-center gap-1.5 rounded bg-teal-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${state === "running" ? "animate-spin" : ""}`} />
          {state === "running" ? "Extracting…" : state === "done" ? "Done" : "Extract Evidence"}
        </button>
        {result && (
          <p className={`text-xs ${state === "error" ? "text-red-400" : "text-teal-400"}`}>{result}</p>
        )}
      </div>
    </div>
  );
}
