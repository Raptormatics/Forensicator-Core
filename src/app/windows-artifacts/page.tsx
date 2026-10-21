"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  AlertCircle, CheckCircle2, ChevronDown, ChevronUp, Clock, Loader2, FileSearch,
  Plus, RefreshCw, Shield, Trash2,
} from "lucide-react";
import { CaseBadge } from "@/components/cases/case-badge";

type FileRow = { id: string; role: string; filename: string; status: string; findingCount: number };
type Upload = {
  id: string;
  hostname: string | null;
  notes: string | null;
  findingCount: number;
  createdAt: string;
  uploadedBy: { email: string; name: string | null } | null;
  case: { id: string; title: string; caseSeq: number; status: string } | null;
  files: FileRow[];
};

const STATUS_ICON: Record<string, React.ReactNode> = {
  ready:      <CheckCircle2 className="h-3.5 w-3.5 text-teal-400" />,
  processing: <Loader2 className="h-3.5 w-3.5 animate-spin text-yellow-400" />,
  queued:     <Clock className="h-3.5 w-3.5 text-zinc-400" />,
  failed:     <AlertCircle className="h-3.5 w-3.5 text-red-400" />,
};

const ROLE_LABEL: Record<string, string> = {
  system_hive: "SYSTEM",
  software_hive: "SOFTWARE",
  security_hive: "SECURITY",
  ntuser_hive: "NTUSER.DAT",
  amcache_hive: "Amcache.hve",
  usrclass_hive: "UsrClass.dat",
  prefetch: "Prefetch",
  lnk: "LNK File",
  jumplist_automatic: "Jump List (Auto)",
  jumplist_custom: "Jump List (Custom)",
};

export default function WindowsArtifactsPage() {
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/windows-artifacts/uploads");
      const data = await res.json();
      setUploads(data.uploads ?? []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 10_000);
    return () => clearInterval(interval);
  }, []);

  async function deleteUpload(id: string) {
    if (!confirm("Delete this collection and every file/finding parsed from it?")) return;
    const res = await fetch(`/api/windows-artifacts/uploads/${id}`, { method: "DELETE" });
    if (!res.ok) window.alert((await res.json().catch(() => ({}))).error ?? "Couldn't delete this upload.");
    load();
  }

  const total    = uploads.length;
  const fileCount = uploads.reduce((s, u) => s + u.files.length, 0);
  const findings = uploads.reduce((s, u) => s + u.findingCount, 0);

  return (
    <div className="min-h-screen">
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-5 px-4 py-8 sm:px-6 lg:px-8">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="flex items-center gap-2 text-sm text-teal-200">
                <FileSearch className="h-4 w-4" />
                Windows Artifact Analysis
              </div>
              <h1 className="mt-3 text-3xl font-semibold tracking-normal text-zinc-50">
                Windows Artifacts
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-400">
                Upload registry hives from a host to extract Shimcache, Amcache, UserAssist, BAM/DAM, and
                Autoruns execution/persistence evidence.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <Link
                href="/windows-artifacts/rules"
                className="flex items-center gap-2 rounded-lg border border-zinc-700 px-4 py-2.5 text-sm font-medium text-zinc-300 hover:bg-zinc-800 transition-colors"
              >
                <Shield className="h-4 w-4" />
                Rules
              </Link>
              <button onClick={load} className="rounded-lg border border-zinc-700 p-2.5 text-zinc-400 hover:bg-zinc-800 transition-colors">
                <RefreshCw className="h-4 w-4" />
              </button>
              <Link
                href="/windows-artifacts/upload"
                className="flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-500 transition-colors"
              >
                <Plus className="h-4 w-4" />
                Upload Artifacts
              </Link>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            {[
              { label: "Collections", value: total },
              { label: "Files Parsed", value: fileCount },
              { label: "Findings", value: findings.toLocaleString() },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
                <p className="text-xs text-zinc-500">{label}</p>
                <p className="mt-1 text-2xl font-semibold text-zinc-100">{value}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        {loading ? (
          <div className="flex items-center justify-center py-20 text-zinc-500">
            <Loader2 className="h-6 w-6 animate-spin" />
          </div>
        ) : uploads.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-zinc-700 py-20 text-center">
            <FileSearch className="h-10 w-10 text-zinc-600 mb-3" />
            <p className="text-sm text-zinc-400 font-medium">No artifact collections yet</p>
            <p className="mt-1 text-xs text-zinc-600">Upload registry hives from a host to get started</p>
            <Link href="/windows-artifacts/upload" className="mt-4 flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500">
              <Plus className="h-4 w-4" /> Upload Artifacts
            </Link>
          </div>
        ) : (
          <div className="rounded-xl border border-zinc-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 bg-zinc-900">
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Host</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Files</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-zinc-500 uppercase tracking-wider">Findings</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Case</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Uploaded</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800 bg-zinc-950">
                {uploads.map((u) => (
                  <tr key={u.id} className="hover:bg-zinc-900/50 transition-colors">
                    <td className="px-4 py-3">
                      <Link href={`/windows-artifacts/${u.id}`} className="text-teal-400 hover:text-teal-300 font-medium">
                        {u.hostname ?? "(unnamed host)"}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <FileSummaryCell files={u.files} />
                    </td>
                    <td className="px-4 py-3 text-right">
                      <span className={u.findingCount > 0 ? "text-orange-400 font-medium" : "text-zinc-500"}>{u.findingCount}</span>
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {u.case ? <CaseBadge kase={u.case} /> : <span className="text-zinc-600">—</span>}
                    </td>
                    <td className="px-4 py-3 text-zinc-500 text-xs whitespace-nowrap">{new Date(u.createdAt).toLocaleString()}</td>
                    <td className="px-4 py-3 text-right">
                      {u.case?.status !== "closed" && (
                        <button onClick={() => deleteUpload(u.id)} className="p-1.5 rounded text-zinc-600 hover:text-red-400 hover:bg-red-900/20 transition-colors" title="Delete">
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

const STATUS_PRIORITY: Record<string, number> = { failed: 0, processing: 1, queued: 2, ready: 3 };

function FileSummaryCell({ files }: { files: FileRow[] }) {
  const [expanded, setExpanded] = useState(false);

  const groups = useMemo(() => {
    const byRole = new Map<string, FileRow[]>();
    for (const f of files) {
      const list = byRole.get(f.role) ?? [];
      list.push(f);
      byRole.set(f.role, list);
    }
    return Array.from(byRole.entries()).map(([role, group]) => {
      const status = group.map((f) => f.status).sort((a, b) => (STATUS_PRIORITY[a] ?? 9) - (STATUS_PRIORITY[b] ?? 9))[0];
      return { role, files: group, status };
    });
  }, [files]);

  const hasMore = files.length > groups.length;

  return (
    <div>
      <div className="flex flex-wrap items-center gap-1.5">
        {groups.map((g) => (
          <span
            key={g.role}
            className={`flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs ${
              g.status === "failed" ? "border-red-900 bg-red-900/20 text-red-300" : "border-zinc-800 bg-zinc-900 text-zinc-400"
            }`}
          >
            {STATUS_ICON[g.status] ?? <Clock className="h-3.5 w-3.5 text-zinc-500" />}
            {ROLE_LABEL[g.role] ?? g.role}
            {g.files.length > 1 && <span className="text-zinc-500">×{g.files.length}</span>}
          </span>
        ))}
        {hasMore && (
          <button
            onClick={() => setExpanded((e) => !e)}
            className="flex items-center gap-0.5 text-xs text-zinc-500 hover:text-zinc-300"
          >
            {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            {expanded ? "Hide files" : `${files.length} files`}
          </button>
        )}
      </div>
      {expanded && (
        <div className="mt-2 space-y-2 border-t border-zinc-800 pt-2">
          {groups.map((g) => (
            <div key={g.role}>
              <p className="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">{ROLE_LABEL[g.role] ?? g.role}</p>
              <div className="flex flex-wrap gap-1.5">
                {g.files.map((f) => (
                  <span
                    key={f.id}
                    title={f.filename}
                    className={`flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs ${
                      f.status === "failed" ? "border-red-900 bg-red-900/10 text-red-300" : "border-zinc-800 bg-zinc-900 text-zinc-400"
                    }`}
                  >
                    {STATUS_ICON[f.status] ?? <Clock className="h-3.5 w-3.5 text-zinc-500" />}
                    {f.filename}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
