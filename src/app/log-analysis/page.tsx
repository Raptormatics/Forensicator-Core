"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertCircle, CheckCircle2, Clock, FileText,
  Loader2, Plus, RefreshCw, ScrollText, Shield, Trash2
} from "lucide-react";
import { CaseBadge } from "@/components/cases/case-badge";

type Upload = {
  id: string;
  filename: string;
  sourceType: string;
  status: string;
  eventCount: number;
  findingCount: number;
  hostname: string | null;
  assetName: string | null;
  errorMessage: string | null;
  createdAt: string;
  uploadedBy: { email: string; name: string | null } | null;
  case: { id: string; title: string; caseSeq: number; status: string } | null;
  _count: { findings: number; iocs: number };
};

const STATUS_ICON: Record<string, React.ReactNode> = {
  ready:      <CheckCircle2 className="h-4 w-4 text-teal-400" />,
  processing: <Loader2 className="h-4 w-4 animate-spin text-yellow-400" />,
  pending:    <Clock className="h-4 w-4 text-zinc-400" />,
  failed:     <AlertCircle className="h-4 w-4 text-red-400" />,
};

export default function LogAnalysisPage() {
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [loading, setLoading] = useState(true);
  const [decoderLabels, setDecoderLabels] = useState<Record<string, string>>({});

  useEffect(() => {
    fetch("/api/log-analysis/decoders")
      .then((r) => r.json())
      .then((data) => {
        const map: Record<string, string> = {};
        for (const d of data.decoders ?? []) {
          map[d.name] = d.title ?? d.name;
        }
        setDecoderLabels(map);
      })
      .catch(() => {});
  }, []);

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/log-analysis/uploads");
      const data = await res.json();
      setUploads(data.uploads ?? []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function deleteUpload(id: string) {
    if (!confirm("Delete this log upload and all its events, IOCs and findings?")) return;
    const res = await fetch(`/api/log-analysis/uploads/${id}`, { method: "DELETE" });
    if (!res.ok) window.alert((await res.json().catch(() => ({}))).error ?? "Couldn't delete this upload.");
    load();
  }

  const total   = uploads.length;
  const ready   = uploads.filter((u) => u.status === "ready").length;
  const findings = uploads.reduce((s, u) => s + u.findingCount, 0);
  const events   = uploads.reduce((s, u) => s + u.eventCount, 0);

  return (
    <div className="min-h-screen">
      {/* Header */}
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-5 px-4 py-8 sm:px-6 lg:px-8">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="flex items-center gap-2 text-sm text-teal-200">
                <ScrollText className="h-4 w-4" />
                Forensicator Enterprise
              </div>
              <h1 className="mt-3 text-3xl font-semibold tracking-normal text-zinc-50">
                Log Analysis
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-400">
                Upload log files from any source, normalize them automatically, extract IOCs, and run detection rules.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <Link
                href="/log-analysis/rules"
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
                href="/log-analysis/upload"
                className="flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-500 transition-colors"
              >
                <Plus className="h-4 w-4" />
                Upload Log
              </Link>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              { label: "Uploads",    value: total },
              { label: "Analyzed",   value: ready },
              { label: "Events",     value: events.toLocaleString() },
              { label: "Findings",   value: findings.toLocaleString() },
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
            <FileText className="h-10 w-10 text-zinc-600 mb-3" />
            <p className="text-sm text-zinc-400 font-medium">No log uploads yet</p>
            <p className="mt-1 text-xs text-zinc-600">Upload your first log file to get started</p>
            <Link
              href="/log-analysis/upload"
              className="mt-4 flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500"
            >
              <Plus className="h-4 w-4" /> Upload Log
            </Link>
          </div>
        ) : (
          <div className="rounded-xl border border-zinc-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 bg-zinc-900">
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">File</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Source</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Status</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-zinc-500 uppercase tracking-wider">Events</th>
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
                        href={`/log-analysis/${u.id}`}
                        className="text-teal-400 hover:text-teal-300 font-medium truncate block"
                      >
                        {u.filename}
                      </Link>
                      {u.errorMessage && (
                        <p className="text-xs text-red-400 mt-0.5 truncate">{u.errorMessage}</p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-zinc-400">
                      {decoderLabels[u.sourceType] ?? u.sourceType}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        {STATUS_ICON[u.status] ?? <Clock className="h-4 w-4 text-zinc-500" />}
                        <span className="text-zinc-300 capitalize">{u.status}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right text-zinc-300">
                      {u.eventCount.toLocaleString()}
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
