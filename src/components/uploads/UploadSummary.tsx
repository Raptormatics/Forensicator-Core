"use client";

import { AlertTriangle, CheckCircle2, ExternalLink, RefreshCw, ShieldAlert } from "lucide-react";
import Link from "next/link";

export interface UploadResult {
  investigation: {
    id: string;
    title: string;
    hostname: string | null;
    finding_count: number;
    url: string;
  };
  findings: {
    total: number;
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
  };
  enrichment?: {
    evidence_rows: number;
    timeline_events: number;
    ioc_feed_matches?: number;
    ioc_queued_for_enrichment?: number;
    warnings?: string[];
  };
}

interface SuccessProps {
  result: UploadResult;
  onUploadAnother: () => void;
}

export function UploadSummary({ result, onUploadAnother }: SuccessProps) {
  const { investigation, findings, enrichment } = result;
  const topSeverities = Object.entries(findings.by_severity)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);

  const SEV_COLORS: Record<string, string> = {
    critical: "text-red-400",
    high:     "text-orange-400",
    medium:   "text-yellow-400",
    low:      "text-blue-400",
    info:     "text-zinc-400",
  };

  return (
    <div className="space-y-6">
      {/* Success header */}
      <div className="flex flex-col items-center gap-3 py-4 text-center">
        <div className="rounded-full bg-teal-900/30 p-4">
          <CheckCircle2 className="h-10 w-10 text-teal-400" />
        </div>
        <div>
          <h2 className="text-lg font-semibold text-zinc-100">Investigation Created</h2>
          <p className="mt-0.5 text-sm text-zinc-500 max-w-sm truncate">{investigation.title}</p>
          {investigation.hostname && (
            <p className="text-xs text-zinc-600 mt-0.5">{investigation.hostname}</p>
          )}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatTile label="Findings" value={findings.total.toLocaleString()} />
        <StatTile label="Evidence" value={(enrichment?.evidence_rows ?? 0).toLocaleString()} />
        <StatTile label="Timeline" value={(enrichment?.timeline_events ?? 0).toLocaleString()} />
        <StatTile label="Severity" value={topSeverities[0]?.[0] ?? "—"} />
      </div>

      {/* Severity breakdown */}
      {topSeverities.length > 0 && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
          <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-zinc-500">By Severity</p>
          <div className="space-y-2">
            {topSeverities.map(([sev, count]) => (
              <div key={sev} className="flex items-center gap-3">
                <span className={`w-16 text-xs font-medium capitalize ${SEV_COLORS[sev] ?? "text-zinc-400"}`}>{sev}</span>
                <div className="flex-1 h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      sev === "critical" ? "bg-red-500" :
                      sev === "high"     ? "bg-orange-500" :
                      sev === "medium"   ? "bg-yellow-500" :
                      sev === "low"      ? "bg-blue-500" : "bg-zinc-500"
                    }`}
                    style={{ width: `${Math.min(100, (count / findings.total) * 100)}%` }}
                  />
                </div>
                <span className="w-10 text-right text-xs text-zinc-500">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Threat-intel auto-enrichment notice */}
      {((enrichment?.ioc_feed_matches ?? 0) > 0 || (enrichment?.ioc_queued_for_enrichment ?? 0) > 0) && (
        <div className="rounded-lg border border-teal-800 bg-teal-950/20 p-3 flex gap-2">
          <ShieldAlert className="h-4 w-4 shrink-0 mt-0.5 text-teal-400" />
          <div className="text-xs text-teal-300 space-y-0.5">
            {(enrichment?.ioc_feed_matches ?? 0) > 0 && (
              <p>{enrichment!.ioc_feed_matches} indicator{enrichment!.ioc_feed_matches !== 1 ? "s" : ""} matched the local URLhaus feed — flagged malicious immediately.</p>
            )}
            {(enrichment?.ioc_queued_for_enrichment ?? 0) > 0 && (
              <p>{enrichment!.ioc_queued_for_enrichment} new indicator{enrichment!.ioc_queued_for_enrichment !== 1 ? "s" : ""} queued for threat-intel enrichment — results will appear on the IOC Intelligence page shortly.</p>
            )}
          </div>
        </div>
      )}

      {/* Warnings */}
      {enrichment?.warnings && enrichment.warnings.length > 0 && (
        <div className="rounded-lg border border-yellow-800 bg-yellow-950/20 p-3 flex gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-yellow-400" />
          <div className="text-xs text-yellow-300 space-y-0.5">
            {enrichment.warnings.map((w, i) => <p key={i}>{w}</p>)}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex flex-col gap-2 sm:flex-row">
        <Link
          href={investigation.url}
          className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-500"
        >
          <ExternalLink className="h-4 w-4" />
          Open Investigation
        </Link>
        <Link
          href={`${investigation.url}/findings`}
          className="flex flex-1 items-center justify-center gap-2 rounded-lg border border-zinc-700 px-4 py-2.5 text-sm font-medium text-zinc-300 hover:bg-zinc-800"
        >
          <ShieldAlert className="h-4 w-4" />
          View Findings
        </Link>
        <button
          onClick={onUploadAnother}
          className="flex items-center justify-center gap-2 rounded-lg border border-zinc-700 px-4 py-2.5 text-sm font-medium text-zinc-400 hover:bg-zinc-800"
        >
          <RefreshCw className="h-4 w-4" />
          Upload Another
        </button>
      </div>
    </div>
  );
}

interface ErrorProps {
  message: string;
  issues?: Record<string, unknown> | string | null;
  onRetry: () => void;
}

export function UploadErrorCard({ message, issues, onRetry }: ErrorProps) {
  return (
    <div className="space-y-4">
      <div className="flex flex-col items-center gap-3 py-4 text-center">
        <div className="rounded-full bg-red-900/30 p-4">
          <AlertTriangle className="h-10 w-10 text-red-400" />
        </div>
        <div>
          <h2 className="text-lg font-semibold text-zinc-100">Upload Failed</h2>
          <p className="mt-1 text-sm text-red-300 max-w-sm">{message}</p>
        </div>
      </div>
      {issues != null ? (
        <pre className="overflow-auto rounded-lg border border-zinc-800 bg-zinc-900 p-3 text-xs text-zinc-500 max-h-40">
          {JSON.stringify(issues, null, 2)}
        </pre>
      ) : null}
      <button
        onClick={onRetry}
        className="w-full rounded-lg border border-zinc-700 px-4 py-2.5 text-sm font-medium text-zinc-300 hover:bg-zinc-800"
      >
        Try Again
      </button>
    </div>
  );
}

function StatTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3 text-center">
      <p className="text-xl font-bold text-zinc-100">{value}</p>
      <p className="mt-0.5 text-xs text-zinc-500">{label}</p>
    </div>
  );
}
