"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, CheckCircle2, Clock, Loader2, FileSearch, RefreshCw,
} from "lucide-react";
import { formatCaseNumber } from "@/lib/cases/case-number";
import { formatDateTime } from "@/lib/utils";

type FileRow = { id: string; role: string; filename: string; status: string; errorMessage: string | null; findingCount: number; profileName: string | null };
type Upload = {
  id: string; hostname: string | null; notes: string | null; findingCount: number; createdAt: string;
  uploadedBy: { email: string; name: string | null } | null;
  case: { id: string; title: string; caseSeq: number } | null;
  files: FileRow[];
};
type ShimcacheRow = { id: string; fileId: string; path: string; lastModified: string | null; executionFlag: boolean | null; order: number };
type AmcacheRow = { id: string; fileId: string; path: string; sha1: string | null; fileSizeBytes: string | null; firstSeen: string | null; publisher: string | null };
type UserAssistRow = { id: string; fileId: string; programPath: string; runCount: number | null; lastExecuted: string | null };
type BamRow = { id: string; fileId: string; sid: string; path: string; lastExecuted: string | null };
type AutorunRow = { id: string; fileId: string; hiveSource: string; keyPath: string; valueName: string | null; valueData: string; category: string };
type PrefetchRow = { id: string; fileId: string; executableName: string; runCount: number | null; lastRunTimes: string[]; firstRunTime: string | null; volumeSerials: string[]; referencedFiles: string[] };
type LnkRow = { id: string; fileId: string; targetPath: string | null; arguments: string | null; workingDirectory: string | null; creationTime: string | null; accessTime: string | null; modificationTime: string | null; driveSerialNumber: string | null; netName: string | null; machineId: string | null };
type JumpListRow = { id: string; fileId: string; source: string; appId: string | null; targetPath: string | null; lastAccessed: string | null; accessRank: number | null; pinned: boolean | null; machineName: string | null };
type ShellbagRow = { id: string; fileId: string; path: string; itemType: string | null; lastModified: string | null; creationTime: string | null; accessTime: string | null };
type Finding = { id: string; title: string; description: string | null; severity: string; matchCount: number; matchedField: string | null; matchedValue: string | null; rule: { id: string; name: string } | null };

type Detail = {
  upload: Upload;
  shimcache: ShimcacheRow[];
  amcache: AmcacheRow[];
  userAssist: UserAssistRow[];
  bam: BamRow[];
  autoruns: AutorunRow[];
  prefetch: PrefetchRow[];
  lnk: LnkRow[];
  jumpList: JumpListRow[];
  shellbags: ShellbagRow[];
  findings: Finding[];
};

type Tab = "overview" | "shimcache" | "amcache" | "userassist" | "bam" | "autoruns" | "prefetch" | "lnk" | "jumplist" | "shellbags" | "findings";

const STATUS_ICON: Record<string, React.ReactNode> = {
  ready:      <CheckCircle2 className="h-3.5 w-3.5 text-teal-400" />,
  processing: <Loader2 className="h-3.5 w-3.5 animate-spin text-yellow-400" />,
  queued:     <Clock className="h-3.5 w-3.5 text-zinc-400" />,
  failed:     <AlertCircle className="h-3.5 w-3.5 text-red-400" />,
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-900/40 text-red-400 border-red-900",
  high:     "bg-orange-900/40 text-orange-400 border-orange-900",
  medium:   "bg-yellow-900/40 text-yellow-400 border-yellow-900",
  low:      "bg-blue-900/40 text-blue-400 border-blue-900",
  info:     "bg-zinc-800 text-zinc-400 border-zinc-700",
};

export default function WindowsArtifactDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<Detail | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>("overview");

  async function load() {
    const res = await fetch(`/api/windows-artifacts/uploads/${id}`);
    if (res.ok) setData(await res.json());
    setLoading(false);
  }

  useEffect(() => { if (id) load(); }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!data) return;
    const stillProcessing = data.upload.files.some((f) => f.status === "queued" || f.status === "processing");
    if (!stillProcessing) return;
    const interval = setInterval(load, 5_000);
    return () => clearInterval(interval);
  }, [data]); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) return <div className="p-8 text-zinc-500">Loading…</div>;
  if (!data) return <div className="p-8 text-red-400">Collection not found.</div>;

  const { upload, shimcache, amcache, userAssist, bam, autoruns, prefetch, lnk, jumpList, shellbags, findings } = data;

  const TABS: { key: Tab; label: string; count: number }[] = [
    { key: "overview", label: "Overview", count: upload.files.length },
    { key: "shimcache", label: "Shimcache", count: shimcache.length },
    { key: "amcache", label: "Amcache", count: amcache.length },
    { key: "userassist", label: "UserAssist", count: userAssist.length },
    { key: "bam", label: "BAM/DAM", count: bam.length },
    { key: "autoruns", label: "Autoruns", count: autoruns.length },
    { key: "prefetch", label: "Prefetch", count: prefetch.length },
    { key: "lnk", label: "LNK Files", count: lnk.length },
    { key: "jumplist", label: "Jump Lists", count: jumpList.length },
    { key: "shellbags", label: "Shellbags", count: shellbags.length },
    { key: "findings", label: "Findings", count: findings.length },
  ];

  return (
    <div className="min-h-screen">
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto w-full max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
          <Link href="/windows-artifacts" className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300 mb-4">
            <ArrowLeft className="h-4 w-4" /> Windows Artifacts
          </Link>
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-sm text-teal-200 mb-1">
                <FileSearch className="h-4 w-4" /> Windows Artifact Analysis
              </div>
              <h1 className="text-2xl font-semibold text-zinc-50">{upload.hostname ?? "(unnamed host)"}</h1>
              {upload.case && (
                <Link href={`/cases/${upload.case.id}`} className="text-sm text-blue-400 hover:text-blue-300 font-mono">
                  {formatCaseNumber(upload.case.caseSeq)} — {upload.case.title}
                </Link>
              )}
            </div>
            <button onClick={load} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-300">
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>
        </div>
      </section>

      <section className="mx-auto w-full max-w-6xl px-4 py-6 sm:px-6 lg:px-8">
        <div className="flex flex-wrap gap-1.5 mb-6">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`rounded-full border px-3 py-1.5 text-xs font-medium transition ${
                tab === t.key ? "border-teal-400/50 bg-teal-400/15 text-teal-200" : "border-zinc-700 bg-zinc-900 text-zinc-400 hover:border-teal-400/30 hover:text-zinc-200"
              }`}
            >
              {t.label} {t.count > 0 && <span className="text-zinc-500">({t.count})</span>}
            </button>
          ))}
        </div>

        {tab === "overview" && (
          <div className="space-y-3">
            {upload.files.map((f) => (
              <div key={f.id} className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {STATUS_ICON[f.status]}
                    <span className="text-sm font-medium text-zinc-200">{f.filename}</span>
                    {f.profileName && <span className="text-xs text-zinc-500">({f.profileName})</span>}
                  </div>
                  <span className="text-xs text-zinc-500 capitalize">{f.status}</span>
                </div>
                {f.errorMessage && <p className="mt-2 text-xs text-red-400">{f.errorMessage}</p>}
              </div>
            ))}
          </div>
        )}

        {tab === "shimcache" && (
          <SimpleTable
            rows={shimcache}
            empty="No Shimcache entries — upload a SYSTEM hive to populate this tab."
            columns={[
              { header: "Path", render: (r) => <span className="font-mono text-xs">{r.path}</span> },
              { header: "Last Modified", render: (r) => r.lastModified ? formatDateTime(new Date(r.lastModified)) : "—" },
              { header: "Executed", render: (r) => r.executionFlag === null ? "—" : r.executionFlag ? "Yes" : "No" },
            ]}
          />
        )}

        {tab === "amcache" && (
          <SimpleTable
            rows={amcache}
            empty="No Amcache entries — upload Amcache.hve to populate this tab."
            columns={[
              { header: "Path", render: (r) => <span className="font-mono text-xs">{r.path}</span> },
              { header: "SHA1", render: (r) => r.sha1 ? <Link href={`/intelligence/ioc/${encodeURIComponent(r.sha1)}`} className="font-mono text-xs text-amber-300 hover:underline">{r.sha1}</Link> : "—" },
              { header: "First Seen", render: (r) => r.firstSeen ? formatDateTime(new Date(r.firstSeen)) : "—" },
            ]}
          />
        )}

        {tab === "userassist" && (
          <SimpleTable
            rows={userAssist}
            empty="No UserAssist entries — upload an NTUSER.DAT to populate this tab."
            columns={[
              { header: "Program", render: (r) => <span className="font-mono text-xs">{r.programPath}</span> },
              { header: "Run Count", render: (r) => r.runCount ?? "—" },
              { header: "Last Executed", render: (r) => r.lastExecuted ? formatDateTime(new Date(r.lastExecuted)) : "—" },
            ]}
          />
        )}

        {tab === "bam" && (
          <SimpleTable
            rows={bam}
            empty="No BAM/DAM entries — upload a SYSTEM hive to populate this tab."
            columns={[
              { header: "Path", render: (r) => <span className="font-mono text-xs">{r.path}</span> },
              { header: "SID", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.sid}</span> },
              { header: "Last Executed", render: (r) => r.lastExecuted ? formatDateTime(new Date(r.lastExecuted)) : "—" },
            ]}
          />
        )}

        {tab === "autoruns" && (
          <SimpleTable
            rows={autoruns}
            empty="No Autorun entries — upload a SYSTEM, SOFTWARE, or NTUSER.DAT hive to populate this tab."
            columns={[
              { header: "Category", render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{r.category}</span> },
              { header: "Key", render: (r) => <span className="font-mono text-xs">{r.keyPath}{r.valueName ? `\\${r.valueName}` : ""}</span> },
              { header: "Value", render: (r) => <span className="font-mono text-xs truncate max-w-[300px] inline-block align-bottom">{r.valueData}</span> },
            ]}
          />
        )}

        {tab === "prefetch" && (
          <SimpleTable
            rows={prefetch}
            empty="No Prefetch entries — upload one or more .pf files to populate this tab."
            columns={[
              { header: "Executable", render: (r) => <span className="font-mono text-xs">{r.executableName}</span> },
              { header: "Run Count", render: (r) => r.runCount ?? "—" },
              { header: "First Run", render: (r) => r.firstRunTime ? formatDateTime(new Date(r.firstRunTime)) : "—" },
              { header: "Last Run", render: (r) => r.lastRunTimes.length > 0 ? formatDateTime(new Date(r.lastRunTimes[0])) : "—" },
              { header: "Referenced Files", render: (r) => <span className="text-xs text-zinc-500">{r.referencedFiles.length}</span> },
            ]}
          />
        )}

        {tab === "lnk" && (
          <SimpleTable
            rows={lnk}
            empty="No LNK entries — upload one or more .lnk files to populate this tab."
            columns={[
              { header: "Target", render: (r) => <span className="font-mono text-xs">{r.targetPath ?? "—"}</span> },
              { header: "Created", render: (r) => r.creationTime ? formatDateTime(new Date(r.creationTime)) : "—" },
              { header: "Accessed", render: (r) => r.accessTime ? formatDateTime(new Date(r.accessTime)) : "—" },
              { header: "Volume Serial", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.driveSerialNumber ?? r.netName ?? "—"}</span> },
              { header: "Machine ID", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.machineId ?? "—"}</span> },
            ]}
          />
        )}

        {tab === "jumplist" && (
          <SimpleTable
            rows={jumpList}
            empty="No Jump List entries — upload one or more .automaticDestinations-ms/.customDestinations-ms files to populate this tab."
            columns={[
              { header: "Target", render: (r) => <span className="font-mono text-xs">{r.targetPath ?? "—"}</span> },
              { header: "Source", render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400 capitalize">{r.source}</span> },
              { header: "App ID", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.appId ?? "—"}</span> },
              { header: "Last Accessed", render: (r) => r.lastAccessed ? formatDateTime(new Date(r.lastAccessed)) : "—" },
              { header: "Rank", render: (r) => r.accessRank ?? "—" },
              { header: "Pinned", render: (r) => r.pinned === null ? "—" : r.pinned ? "Yes" : "No" },
            ]}
          />
        )}

        {tab === "shellbags" && (
          <SimpleTable
            rows={shellbags}
            empty="No Shellbag entries — upload a UsrClass.dat to populate this tab."
            columns={[
              { header: "Path", render: (r) => <span className="font-mono text-xs">{r.path}</span> },
              { header: "Type", render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{r.itemType ?? "—"}</span> },
              { header: "Created", render: (r) => r.creationTime ? formatDateTime(new Date(r.creationTime)) : "—" },
              { header: "Accessed", render: (r) => r.accessTime ? formatDateTime(new Date(r.accessTime)) : "—" },
              { header: "Modified", render: (r) => r.lastModified ? formatDateTime(new Date(r.lastModified)) : "—" },
            ]}
          />
        )}

        {tab === "findings" && (
          <div className="space-y-2">
            {findings.length === 0 ? (
              <p className="text-sm text-zinc-600 py-8 text-center">No findings yet.</p>
            ) : (
              findings.map((f) => (
                <div key={f.id} className="rounded-lg border border-zinc-800 bg-zinc-900 p-3">
                  <div className="flex items-center gap-2">
                    <span className={`rounded border px-1.5 py-0.5 text-xs capitalize ${SEVERITY_BADGE[f.severity] ?? SEVERITY_BADGE.info}`}>{f.severity}</span>
                    <span className="text-sm font-medium text-zinc-200">{f.title}</span>
                    {f.matchCount > 1 && <span className="text-xs text-zinc-500">×{f.matchCount}</span>}
                  </div>
                  {f.description && <p className="mt-1 text-xs text-zinc-500">{f.description}</p>}
                  {f.matchedValue && <p className="mt-1 font-mono text-xs text-teal-400 truncate">{f.matchedValue}</p>}
                </div>
              ))
            )}
          </div>
        )}
      </section>
    </div>
  );
}

function SimpleTable<T extends { id: string }>({
  rows, columns, empty,
}: {
  rows: T[];
  columns: { header: string; render: (row: T) => React.ReactNode }[];
  empty: string;
}) {
  if (rows.length === 0) {
    return <p className="text-sm text-zinc-600 py-12 text-center rounded-xl border border-dashed border-zinc-800">{empty}</p>;
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-zinc-800 bg-zinc-950/80">
            {columns.map((c) => <th key={c.header} className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">{c.header}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className="border-b border-zinc-800/40 hover:bg-zinc-900/40">
              {columns.map((c) => <td key={c.header} className="px-4 py-2 text-zinc-200">{c.render(row)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
