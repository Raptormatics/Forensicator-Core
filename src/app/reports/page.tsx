"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Download, RefreshCw, FileText } from "lucide-react";
import { formatCaseNumber } from "@/lib/cases/case-number";

type Report = {
  id: string;
  type: string;
  format: string;
  status: string;
  filePath: string | null;
  fileSize: number | null;
  createdAt: string;
  investigation: { id: string; hostname: string | null } | null;
  case: { id: string; title: string; caseSeq: number } | null;
  generatedBy: { email: string; name: string | null } | null;
};

const STATUS_COLOR: Record<string, string> = {
  queued:     "text-yellow-400",
  generating: "text-blue-400",
  ready:      "text-green-400",
  failed:     "text-red-400",
};

const FORMAT_ICONS: Record<string, string> = {
  pdf:  "📄",
  csv:  "📊",
  json: "📋",
  zip:  "🗜️",
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    const res = await fetch("/api/reports/list");
    if (res.ok) setReports((await res.json()).reports ?? []);
    setLoading(false);
  }

  useEffect(() => { load(); }, []);

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">Reports</h1>
          <p className="text-sm text-zinc-500 mt-0.5">All generated reports across all investigations</p>
        </div>
        <button onClick={load} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-200">
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {loading ? (
        <div className="text-center py-16 text-zinc-600">Loading reports…</div>
      ) : reports.length === 0 ? (
        <div className="text-center py-16 text-zinc-600">
          <FileText className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p>No reports generated yet.</p>
          <p className="text-xs mt-2">Generate reports from a case&apos;s detail page.</p>
        </div>
      ) : (
        <div className="rounded-xl border border-zinc-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900 text-left">
                <th className="px-4 py-3 font-medium text-zinc-400">Report</th>
                <th className="px-4 py-3 font-medium text-zinc-400">Case</th>
                <th className="px-4 py-3 font-medium text-zinc-400">Status</th>
                <th className="px-4 py-3 font-medium text-zinc-400">Size</th>
                <th className="px-4 py-3 font-medium text-zinc-400">Requested By</th>
                <th className="px-4 py-3 font-medium text-zinc-400">Created</th>
                <th className="px-4 py-3 font-medium text-zinc-400">Download</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {reports.map((r) => (
                <tr key={r.id} className="bg-zinc-950 hover:bg-zinc-900 transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span>{FORMAT_ICONS[r.format] ?? "📄"}</span>
                      <div>
                        <div className="text-zinc-200 font-medium capitalize">{r.type.replace("-", " ")}</div>
                        <div className="text-xs text-zinc-600 uppercase">{r.format}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {r.case ? (
                      <Link href={`/cases/${r.case.id}`} className="text-blue-400 hover:text-blue-300">
                        {formatCaseNumber(r.case.caseSeq)} · {r.case.title}
                      </Link>
                    ) : r.investigation ? (
                      <Link href={`/investigations/${r.investigation.id}`} className="text-teal-400 hover:text-teal-300">
                        {r.investigation.hostname}
                      </Link>
                    ) : <span className="text-zinc-600">—</span>}
                  </td>
                  <td className={`px-4 py-3 text-xs font-medium ${STATUS_COLOR[r.status] ?? "text-zinc-400"}`}>
                    {r.status}
                  </td>
                  <td className="px-4 py-3 text-zinc-500 text-xs">
                    {r.fileSize ? formatBytes(r.fileSize) : "—"}
                  </td>
                  <td className="px-4 py-3 text-zinc-500 text-xs">
                    {r.generatedBy?.name ?? r.generatedBy?.email ?? "—"}
                  </td>
                  <td className="px-4 py-3 text-zinc-600 text-xs">
                    {new Date(r.createdAt).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3">
                    {r.status === "ready" && r.filePath ? (
                      <a
                        href={`/api/reports/${r.id}/download`}
                        className="inline-flex items-center gap-1 rounded-md border border-zinc-700 px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800"
                      >
                        <Download className="h-3 w-3" /> Download
                      </a>
                    ) : (
                      <span className="text-zinc-700 text-xs">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
