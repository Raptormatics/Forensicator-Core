"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertCircle, CheckCircle2, Clock, Loader2, MemoryStick,
  Plus, RefreshCw, Shield, Trash2,
} from "lucide-react";
import { CaseBadge } from "@/components/cases/case-badge";
import { ArchiveButton } from "@/components/cases/archive-button";

type Upload = {
  id: string;
  filename: string;
  status: string;
  fileSize: string;
  processCount: number;
  connectionCount: number;
  findingCount: number;
  iocCount: number;
  osBuild: string | null;
  osArch: string | null;
  hostname: string | null;
  assetName: string | null;
  errorMessage: string | null;
  createdAt: string;
  uploadedBy: { email: string; name: string | null } | null;
  case: { id: string; title: string; caseSeq: number; status: string; archivedAt: string | null } | null;
};

const STATUS_ICON: Record<string, React.ReactNode> = {
  ready:      <CheckCircle2 className="h-4 w-4 text-teal-400" />,
  processing: <Loader2 className="h-4 w-4 animate-spin text-yellow-400" />,
  queued:     <Clock className="h-4 w-4 text-zinc-400" />,
  failed:     <AlertCircle className="h-4 w-4 text-red-400" />,
};

function formatBytes(bytes: string): string {
  const n = Number(bytes);
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

// An upload in any other state is still uploading or being analysed.
const FINAL_STATUSES = new Set(["ready", "failed", "error", "cancelled", "canceled"]);

export default function RamAnalysisPage() {
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [loading, setLoading] = useState(true);

  // `loading` starts true and only the first fetch clears it — later
  // refreshes update the table in place instead of swapping it for
  // "Loading…" (which made the page visibly blink every 10 seconds).
  async function load() {
    try {
      const res = await fetch("/api/ram-analysis/uploads");
      const data = await res.json();
      setUploads(data.uploads ?? []);
    } finally {
      setLoading(false);
    }
  }

  // Poll only while something is still being processed.
  const busy = uploads.some((u) => !FINAL_STATUSES.has(u.status));
  useEffect(() => { load(); }, []);
  useEffect(() => {
    if (!busy) return;
    const interval = setInterval(load, 10_000);
    return () => clearInterval(interval);
  }, [busy]);

  async function deleteUpload(id: string) {
    if (!confirm("Delete this RAM upload and all its processes, connections, IOCs and findings?")) return;
    const res = await fetch(`/api/ram-analysis/uploads/${id}`, { method: "DELETE" });
    if (!res.ok) window.alert((await res.json().catch(() => ({}))).error ?? "Couldn't delete this upload.");
    load();
  }

  const total    = uploads.length;
  const ready    = uploads.filter((u) => u.status === "ready").length;
  const findings = uploads.reduce((s, u) => s + u.findingCount, 0);
  const processes = uploads.reduce((s, u) => s + u.processCount, 0);

  return (
    <div className="min-h-screen">
      {/* Header */}
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-5 px-4 py-8 sm:px-6 lg:px-8">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="flex items-center gap-2 text-sm text-teal-200">
                <MemoryStick className="h-4 w-4" />
                Forensicator Enterprise
              </div>
              <h1 className="mt-3 text-3xl font-semibold tracking-normal text-zinc-50">
                RAM Analysis
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-400">
                Upload Windows memory images to extract processes, network connections, and injected-code findings, and run detection rules against them. Windows-only in this release.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <Link
                href="/ram-analysis/rules"
                className="flex items-center gap-2 rounded-lg border border-zinc-700 px-4 py-2.5 text-sm font-medium text-zinc-300 hover:bg-zinc-800 transition-colors"
              >
                <Shield className="h-4 w-4" />
                Rules
              </Link>
              <button
                onClick={load}
                className="rounded-lg border border-zinc-700 p-2.5 text-zinc-400 hover:bg-zinc-800 transition-colors"
              >
                <RefreshCw className="h-4 w-4" />
              </button>
              <Link
                href="/ram-analysis/upload"
                className="flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-500 transition-colors"
              >
                <Plus className="h-4 w-4" />
                Upload Memory Image
              </Link>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              { label: "Uploads",   value: total },
              { label: "Analyzed",  value: ready },
              { label: "Processes", value: processes.toLocaleString() },
              { label: "Findings",  value: findings.toLocaleString() },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
                <p className="text-xs text-zinc-500">{label}</p>
                <p className="mt-1 text-2xl font-semibold text-zinc-100">{value}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Table */}
      <section className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        {loading ? (
          <div className="flex items-center justify-center py-20 text-zinc-500">
            <Loader2 className="h-6 w-6 animate-spin" />
          </div>
        ) : uploads.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-zinc-700 py-20 text-center">
            <MemoryStick className="h-10 w-10 text-zinc-600 mb-3" />
            <p className="text-sm text-zinc-400 font-medium">No RAM uploads yet</p>
            <p className="mt-1 text-xs text-zinc-600">Upload your first Windows memory image to get started</p>
            <Link
              href="/ram-analysis/upload"
              className="mt-4 flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500"
            >
              <Plus className="h-4 w-4" /> Upload Memory Image
            </Link>
          </div>
        ) : (
          <div className="rounded-xl border border-zinc-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 bg-zinc-900">
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">File</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">OS</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-zinc-500 uppercase tracking-wider">Processes</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-zinc-500 uppercase tracking-wider">Size</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-zinc-500 uppercase tracking-wider">Findings</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Host</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Case</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Uploaded</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800 bg-zinc-950">
                {uploads.map((u) => (
                  <tr key={u.id} className="hover:bg-zinc-900/50 transition-colors">
                    <td className="px-4 py-3 max-w-[200px]">
                      <Link
                        href={`/ram-analysis/${u.id}`}
                        className="text-teal-400 hover:text-teal-300 font-medium truncate block"
                      >
                        {u.filename}
                      </Link>
                      {u.errorMessage && (
                        <p className="text-xs text-red-400 mt-0.5 truncate">{u.errorMessage}</p>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        {STATUS_ICON[u.status] ?? <Clock className="h-4 w-4 text-zinc-500" />}
                        <span className="text-zinc-300 capitalize">{u.status}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-zinc-400 text-xs">
                      {u.osBuild ? `${u.osBuild}${u.osArch ? ` (${u.osArch})` : ""}` : "—"}
                    </td>
                    <td className="px-4 py-3 text-right text-zinc-300">
                      {u.processCount.toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right text-zinc-400 text-xs">
                      {formatBytes(u.fileSize)}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <span className={u.findingCount > 0 ? "text-orange-400 font-medium" : "text-zinc-500"}>
                        {u.findingCount}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-zinc-400 text-xs">
                      {u.assetName ?? u.hostname ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {u.case ? <CaseBadge kase={u.case} /> : <span className="text-zinc-600">—</span>}
                    </td>
                    <td className="px-4 py-3 text-zinc-500 text-xs whitespace-nowrap">
                      {new Date(u.createdAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {!u.case && <ArchiveButton compact type="ram" id={u.id} action="archive" onDone={load} />}
                      {u.case?.status !== "closed" && (
                        <button
                          onClick={() => deleteUpload(u.id)}
                          className="p-1.5 rounded text-zinc-600 hover:text-red-400 hover:bg-red-900/20 transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
