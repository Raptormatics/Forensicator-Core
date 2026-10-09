"use client";

import { BrainCircuit, Loader2, RotateCw, Sparkles } from "lucide-react";
import { useEffect, useRef, useState } from "react";

type AiAnalysis = {
  why_flagged?: string | null;
  investigation_questions?: string[];
  recommended_next_steps?: string[];
  error?: string;
};

type Status = "not_queued" | "pending" | "processing" | "complete" | "failed" | string;

type Props = {
  findingDbId: string;
  initialStatus: Status;
  initialSummary: string | null;
  initialConfidence: number | null;
  initialModel: string | null;
  initialAnalysis: AiAnalysis | null;
};

const POLL_INTERVAL_MS = 4000;
const ACTIVE_STATUSES = new Set(["pending", "processing"]);

export function AiAnalysisPanel({
  findingDbId,
  initialStatus,
  initialSummary,
  initialConfidence,
  initialModel,
  initialAnalysis,
}: Props) {
  const [status, setStatus] = useState<Status>(initialStatus);
  const [summary, setSummary] = useState(initialSummary);
  const [confidence, setConfidence] = useState(initialConfidence);
  const [model, setModel] = useState(initialModel);
  const [analysis, setAnalysis] = useState<AiAnalysis | null>(initialAnalysis);
  const [triggering, setTriggering] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (ACTIVE_STATUSES.has(status)) {
      pollRef.current = setInterval(poll, POLL_INTERVAL_MS);
      return () => {
        if (pollRef.current) clearInterval(pollRef.current);
      };
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  async function poll() {
    try {
      const res = await fetch(`/api/findings/${findingDbId}/analyze`);
      if (!res.ok) return;
      const data = await res.json();
      setStatus(data.aiStatus);
      setSummary(data.aiSummary);
      setConfidence(data.aiConfidence);
      setModel(data.aiModel);
      setAnalysis(data.aiAnalysis);
    } catch {
      // transient — next poll tick will retry
    }
  }

  async function trigger(force: boolean) {
    setTriggering(true);
    setError(null);
    try {
      const res = await fetch(`/api/findings/${findingDbId}/analyze`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ force }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Failed to request analysis.");
        return;
      }
      setStatus(data.aiStatus ?? "pending");
    } catch {
      setError("Failed to request analysis.");
    } finally {
      setTriggering(false);
    }
  }

  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-950/55">
      <div className="flex items-center justify-between gap-2 border-b border-zinc-800 px-4 py-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
          <BrainCircuit className="h-4 w-4 text-teal-300" />
          Forensicator AI
        </div>
        <StatusBadge status={status} />
      </div>

      <div className="space-y-3 p-4">
        {error ? <p className="text-xs text-red-400">{error}</p> : null}

        {status === "not_queued" || status === "failed" ? (
          <div className="space-y-2">
            {status === "failed" && analysis?.error ? (
              <p className="text-xs text-red-400">{analysis.error}</p>
            ) : (
              <p className="text-sm text-zinc-500">
                Ask the local Ollama-backed model for a plain-language read on this finding — why it was flagged,
                what to check next, and how confident to be.
              </p>
            )}
            <button
              onClick={() => trigger(status === "failed")}
              disabled={triggering}
              className="flex items-center gap-2 rounded-lg bg-teal-700 px-3 py-1.5 text-xs font-semibold text-white hover:bg-teal-600 disabled:opacity-60"
            >
              {triggering ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
              {status === "failed" ? "Retry analysis" : "Analyze with AI"}
            </button>
          </div>
        ) : null}

        {ACTIVE_STATUSES.has(status) ? (
          <div className="flex items-center gap-2 text-sm text-zinc-400">
            <Loader2 className="h-4 w-4 animate-spin text-teal-300" />
            {status === "pending" ? "Queued for analysis…" : "Analyzing…"}
          </div>
        ) : null}

        {status === "complete" && summary ? (
          <div className="space-y-3">
            <p className="text-sm leading-6 text-zinc-300">{summary}</p>

            {analysis?.why_flagged ? (
              <div>
                <p className="text-xs uppercase tracking-normal text-zinc-500">Why flagged</p>
                <p className="mt-1 text-sm text-zinc-300">{analysis.why_flagged}</p>
              </div>
            ) : null}

            {analysis?.investigation_questions && analysis.investigation_questions.length > 0 ? (
              <div>
                <p className="text-xs uppercase tracking-normal text-zinc-500">Investigation questions</p>
                <ul className="mt-1 list-disc space-y-1 pl-4 text-sm text-zinc-300">
                  {analysis.investigation_questions.map((q, i) => <li key={i}>{q}</li>)}
                </ul>
              </div>
            ) : null}

            {analysis?.recommended_next_steps && analysis.recommended_next_steps.length > 0 ? (
              <div>
                <p className="text-xs uppercase tracking-normal text-zinc-500">Recommended next steps</p>
                <ul className="mt-1 list-disc space-y-1 pl-4 text-sm text-zinc-300">
                  {analysis.recommended_next_steps.map((s, i) => <li key={i}>{s}</li>)}
                </ul>
              </div>
            ) : null}

            <div className="flex items-center justify-between border-t border-zinc-800 pt-2 text-xs text-zinc-500">
              <span>{model ? `Model: ${model}` : null}{confidence !== null ? ` · Confidence: ${confidence}%` : null}</span>
              <button
                onClick={() => trigger(true)}
                disabled={triggering}
                className="flex items-center gap-1 text-zinc-500 hover:text-teal-300 disabled:opacity-60"
                title="Re-run analysis"
              >
                <RotateCw className="h-3 w-3" /> Re-analyze
              </button>
            </div>
          </div>
        ) : null}
      </div>
    </section>
  );
}

function StatusBadge({ status }: { status: Status }) {
  const styles: Record<string, string> = {
    not_queued: "border-zinc-700 bg-zinc-900 text-zinc-400",
    pending: "border-amber-400/30 bg-amber-400/10 text-amber-200",
    processing: "border-amber-400/30 bg-amber-400/10 text-amber-200",
    complete: "border-teal-400/30 bg-teal-400/10 text-teal-100",
    failed: "border-red-900 bg-red-950/50 text-red-400",
  };
  const labels: Record<string, string> = {
    not_queued: "Not analyzed",
    pending: "Queued",
    processing: "Analyzing",
    complete: "Analyzed",
    failed: "Failed",
  };
  const cls = styles[status] ?? styles.not_queued;
  const label = labels[status] ?? status;
  return <span className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${cls}`}>{label}</span>;
}
