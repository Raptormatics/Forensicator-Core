"use client";

import { FileText, Loader2 } from "lucide-react";
import { useState } from "react";

type ReportFormat = "pdf" | "csv" | "json" | "zip";
type ReportType   = "executive" | "technical";

type GeneratedReport = {
  id: string;
  status: string;
  type: string;
  format: string;
};

export function ReportGenerator({ caseId }: { caseId: string }) {
  const [type,   setType]   = useState<ReportType>("executive");
  const [format, setFormat] = useState<ReportFormat>("pdf");
  const [state,  setState]  = useState<"idle" | "queuing" | "polling" | "ready" | "error">("idle");
  const [report, setReport] = useState<GeneratedReport | null>(null);
  const [msg,    setMsg]    = useState<string | null>(null);

  async function generate() {
    setState("queuing");
    setMsg(null);
    try {
      const res = await fetch("/api/reports/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ caseId, type, format }),
      });
      const json = await res.json();
      if (!res.ok) { setState("error"); setMsg(json.message ?? "Failed to queue report."); return; }

      const r = json.report as GeneratedReport;
      setReport(r);
      setState("polling");
      poll(r.id);
    } catch (e) {
      setState("error");
      setMsg(e instanceof Error ? e.message : "Unexpected error.");
    }
  }

  async function poll(id: string, attempts = 0) {
    if (attempts > 60) { setState("error"); setMsg("Timed out waiting for report."); return; }
    await new Promise((r) => setTimeout(r, 2000));
    const res  = await fetch(`/api/reports/${id}`);
    const json = await res.json();
    const status: string = json.report?.status ?? "queued";
    setReport((prev) => prev ? { ...prev, status } : prev);

    if (status === "ready")  { setState("ready"); return; }
    if (status === "failed") { setState("error"); setMsg(json.report?.errorMessage ?? "Report generation failed."); return; }
    poll(id, attempts + 1);
  }

  return (
    <div className="space-y-3 rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-400 flex items-center gap-1.5">
        <FileText className="h-3.5 w-3.5" />
        Generate Report
      </h3>

      <div className="flex flex-wrap gap-2">
        {/* Report type */}
        <div className="flex rounded border border-zinc-700 overflow-hidden text-xs">
          {(["executive", "technical"] as ReportType[]).map((t) => (
            <button
              key={t}
              onClick={() => setType(t)}
              className={`px-3 py-1.5 capitalize transition-colors ${type === t ? "bg-teal-700 text-white" : "bg-zinc-900 text-zinc-400 hover:bg-zinc-800"}`}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Format */}
        <div className="flex rounded border border-zinc-700 overflow-hidden text-xs">
          {(["pdf", "csv", "json", "zip"] as ReportFormat[]).map((f) => (
            <button
              key={f}
              onClick={() => setFormat(f)}
              className={`px-3 py-1.5 uppercase transition-colors ${format === f ? "bg-teal-700 text-white" : "bg-zinc-900 text-zinc-400 hover:bg-zinc-800"}`}
            >
              {f}
            </button>
          ))}
        </div>

        <button
          onClick={generate}
          disabled={state === "queuing" || state === "polling"}
          className="inline-flex items-center gap-1.5 rounded bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-500 disabled:opacity-50"
        >
          {(state === "queuing" || state === "polling") && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
          {state === "queuing" ? "Queuing…" : state === "polling" ? `Generating (${report?.status ?? "…"})` : "Generate"}
        </button>
      </div>

      {state === "ready" && report && (
        <div className="flex items-center gap-3 rounded bg-teal-900/30 border border-teal-700/30 px-3 py-2">
          <span className="text-xs text-teal-300">Report ready.</span>
          <a
            href={`/api/reports/${report.id}/download`}
            className="rounded bg-teal-600 px-3 py-1 text-xs font-medium text-white hover:bg-teal-500"
          >
            Download {format.toUpperCase()}
          </a>
        </div>
      )}

      {state === "error" && msg && (
        <p className="rounded bg-red-900/30 border border-red-700/30 px-3 py-2 text-xs text-red-400">{msg}</p>
      )}
    </div>
  );
}
