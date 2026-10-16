"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, CheckCircle2, Clock, Loader2, FileSearch, RefreshCw, Search, Download,
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
type MftRow = { id: string; fileId: string; mftEntryNumber: number; name: string; path: string | null; isAllocated: boolean; isDirectory: boolean; creationTime: string | null; entryModificationTime: string | null; fileSize: string | null; hasAlternateDataStreams: boolean };
type UsnJrnlRow = { id: string; fileId: string; usn: string; timestamp: string | null; reason: string[]; fileName: string | null };
type SrumRow = { id: string; fileId: string; tableName: string; providerLabel: string | null; timestamp: string | null; appId: string | null; userSid: string | null; details: Record<string, unknown> };
type WerReportRow = { id: string; fileId: string; sourceFileName: string; eventType: string | null; eventTime: string | null; appName: string | null; appVersion: string | null; faultModuleName: string | null; exceptionCode: string | null; exceptionOffset: string | null };
type WerDumpRow = { id: string; fileId: string; sourceFileName: string; exceptionCode: string | null; exceptionAddress: string | null; processId: number | null; processCreateTime: string | null; osVersion: string | null; moduleList: { name: string; base_address: string | null; size: number }[] };
type RecycleBinRow = { id: string; fileId: string; sid: string; sourceFileName: string; formatVersion: number; originalPath: string; deletedTime: string | null; fileSizeBytes: string | null };
type NotificationRow = { id: string; fileId: string; profileName: string | null; arrivalTime: string | null; notifType: string | null; tag: string | null; handlerLabel: string | null; payload: string | null };
type SearchIndexRow = { id: string; fileId: string; tableName: string; recordIndex: number; details: Record<string, unknown> };
type QuarantineEntryRow = { id: string; fileId: string; sourceFileName: string; detectionName: string | null; timestamp: string | null; threatId: string | null; resources: { detection_path: string | null; detection_type: string | null }[] };
type QuarantinePayloadRow = { id: string; fileId: string; sourceFileName: string; magicValid: boolean; sha256: string | null; decryptedSizeBytes: string | null; fileTypeSniff: string | null };
type BitsJobRow = { id: string; fileId: string; name: string | null; destFn: string | null; srcFn: string | null; state: string | null; ctime: string | null; isCarved: boolean };
type TimelineRow = { id: string; fileId: string; profileName: string | null; startTime: string | null; activityKind: string; appDisplayName: string | null; description: string | null; packageIdentifier: string | null; activeDurationSeconds: number | null; reportingApp: string | null };
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
  mft: MftRow[];
  usnJrnl: UsnJrnlRow[];
  srum: SrumRow[];
  werReports: WerReportRow[];
  werDumps: WerDumpRow[];
  recycleBin: RecycleBinRow[];
  notifications: NotificationRow[];
  searchIndex: SearchIndexRow[];
  quarantineEntries: QuarantineEntryRow[];
  quarantinePayloads: QuarantinePayloadRow[];
  bitsJobs: BitsJobRow[];
  timeline: TimelineRow[];
  findings: Finding[];
};

type Tab = "overview" | "shimcache" | "amcache" | "userassist" | "bam" | "autoruns" | "prefetch" | "lnk" | "jumplist" | "shellbags" | "mft" | "usnjrnl" | "srum"
  | "wer" | "werdump" | "recyclebin" | "notifications" | "search" | "quarantine" | "quarantinepayloads" | "bits" | "timeline" | "findings";

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

function downloadBlob(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function csvEscape(v: string): string {
  return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

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

  const {
    upload, shimcache, amcache, userAssist, bam, autoruns, prefetch, lnk, jumpList, shellbags, mft, usnJrnl, srum,
    werReports, werDumps, recycleBin, notifications, searchIndex, quarantineEntries, quarantinePayloads, bitsJobs,
    timeline, findings,
  } = data;

  // filename carries the source subfolder when the upload form's folder
  // picker was used (e.g. "FAVOUR/Desktop/foo.lnk") — surfaced as a Source
  // column below so LNK/Jump List entries stay traceable to which
  // Desktop/Links/OneDrive/profile folder they actually came from.
  const fileNameById = new Map(upload.files.map((f) => [f.id, f.filename]));

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
    { key: "mft", label: "$MFT", count: mft.length },
    { key: "usnjrnl", label: "$UsnJrnl:$J", count: usnJrnl.length },
    { key: "srum", label: "SRUM", count: srum.length },
    { key: "wer", label: "WER Reports", count: werReports.length },
    { key: "werdump", label: "WER Dumps", count: werDumps.length },
    { key: "recyclebin", label: "Recycle Bin", count: recycleBin.length },
    { key: "notifications", label: "Notifications", count: notifications.length },
    { key: "search", label: "Search Index", count: searchIndex.length },
    { key: "quarantine", label: "Quarantine Entries", count: quarantineEntries.length },
    { key: "quarantinepayloads", label: "Quarantine Payloads", count: quarantinePayloads.length },
    { key: "bits", label: "BITS", count: bitsJobs.length },
    { key: "timeline", label: "Timeline", count: timeline.length },
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
            exportName={`windows-artifacts-${id}-shimcache`}
            empty="No Shimcache entries — upload a SYSTEM hive to populate this tab."
            columns={[
              { header: "Path", wrap: true, csv: (r) => r.path, render: (r) => <span className="font-mono text-xs">{r.path}</span> },
              { header: "Last Modified", csv: (r) => r.lastModified ? formatDateTime(new Date(r.lastModified)) : "", render: (r) => r.lastModified ? formatDateTime(new Date(r.lastModified)) : "—" },
              { header: "Executed", csv: (r) => r.executionFlag === null ? "" : r.executionFlag ? "Yes" : "No", render: (r) => r.executionFlag === null ? "—" : r.executionFlag ? "Yes" : "No" },
            ]}
          />
        )}

        {tab === "amcache" && (
          <SimpleTable
            rows={amcache}
            exportName={`windows-artifacts-${id}-amcache`}
            empty="No Amcache entries — upload Amcache.hve to populate this tab."
            columns={[
              { header: "Path", wrap: true, csv: (r) => r.path, render: (r) => <span className="font-mono text-xs">{r.path}</span> },
              { header: "SHA1", wrap: true, csv: (r) => r.sha1 ?? "", render: (r) => r.sha1 ? <Link href={`/intelligence/ioc/${encodeURIComponent(r.sha1)}`} className="font-mono text-xs text-amber-300 hover:underline">{r.sha1}</Link> : "—" },
              { header: "First Seen", csv: (r) => r.firstSeen ? formatDateTime(new Date(r.firstSeen)) : "", render: (r) => r.firstSeen ? formatDateTime(new Date(r.firstSeen)) : "—" },
            ]}
          />
        )}

        {tab === "userassist" && (
          <SimpleTable
            rows={userAssist}
            exportName={`windows-artifacts-${id}-userassist`}
            empty="No UserAssist entries — upload an NTUSER.DAT to populate this tab."
            columns={[
              { header: "Program", wrap: true, csv: (r) => r.programPath, render: (r) => <span className="font-mono text-xs">{r.programPath}</span> },
              { header: "Run Count", csv: (r) => String(r.runCount ?? ""), render: (r) => r.runCount ?? "—" },
              { header: "Last Executed", csv: (r) => r.lastExecuted ? formatDateTime(new Date(r.lastExecuted)) : "", render: (r) => r.lastExecuted ? formatDateTime(new Date(r.lastExecuted)) : "—" },
            ]}
          />
        )}

        {tab === "bam" && (
          <SimpleTable
            rows={bam}
            exportName={`windows-artifacts-${id}-bam`}
            empty="No BAM/DAM entries — upload a SYSTEM hive to populate this tab."
            columns={[
              { header: "Path", wrap: true, csv: (r) => r.path, render: (r) => <span className="font-mono text-xs">{r.path}</span> },
              { header: "SID", wrap: true, csv: (r) => r.sid, render: (r) => <span className="font-mono text-xs text-zinc-500">{r.sid}</span> },
              { header: "Last Executed", csv: (r) => r.lastExecuted ? formatDateTime(new Date(r.lastExecuted)) : "", render: (r) => r.lastExecuted ? formatDateTime(new Date(r.lastExecuted)) : "—" },
            ]}
          />
        )}

        {tab === "autoruns" && (
          <SimpleTable
            rows={autoruns}
            exportName={`windows-artifacts-${id}-autoruns`}
            empty="No Autorun entries — upload a SYSTEM, SOFTWARE, or NTUSER.DAT hive to populate this tab."
            filter={{ label: "Category", getValue: (r) => r.category }}
            columns={[
              { header: "Category", csv: (r) => r.category, render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{r.category}</span> },
              { header: "Key", wrap: true, csv: (r) => r.keyPath + (r.valueName ? `\\${r.valueName}` : ""), render: (r) => <span className="font-mono text-xs">{r.keyPath}{r.valueName ? `\\${r.valueName}` : ""}</span> },
              { header: "Value", wrap: true, csv: (r) => r.valueData, render: (r) => <span className="font-mono text-xs">{r.valueData}</span> },
            ]}
          />
        )}

        {tab === "prefetch" && (
          <SimpleTable
            rows={prefetch}
            exportName={`windows-artifacts-${id}-prefetch`}
            empty="No Prefetch entries — upload one or more .pf files to populate this tab."
            columns={[
              { header: "Executable", wrap: true, csv: (r) => r.executableName, render: (r) => <span className="font-mono text-xs">{r.executableName}</span> },
              { header: "Run Count", csv: (r) => String(r.runCount ?? ""), render: (r) => r.runCount ?? "—" },
              { header: "First Run", csv: (r) => r.firstRunTime ? formatDateTime(new Date(r.firstRunTime)) : "", render: (r) => r.firstRunTime ? formatDateTime(new Date(r.firstRunTime)) : "—" },
              { header: "Last Run", csv: (r) => r.lastRunTimes.length > 0 ? formatDateTime(new Date(r.lastRunTimes[0])) : "", render: (r) => r.lastRunTimes.length > 0 ? formatDateTime(new Date(r.lastRunTimes[0])) : "—" },
              { header: "Referenced Files", csv: (r) => String(r.referencedFiles.length), render: (r) => <span className="text-xs text-zinc-500">{r.referencedFiles.length}</span> },
            ]}
          />
        )}

        {tab === "lnk" && (
          <SimpleTable
            rows={lnk}
            exportName={`windows-artifacts-${id}-lnk`}
            empty="No LNK entries — upload one or more .lnk files to populate this tab."
            columns={[
              { header: "Target", wrap: true, csv: (r) => r.targetPath ?? "", render: (r) => <span className="font-mono text-xs">{r.targetPath ?? "—"}</span> },
              { header: "Source", wrap: true, csv: (r) => fileNameById.get(r.fileId) ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{fileNameById.get(r.fileId) ?? "—"}</span> },
              { header: "Created", csv: (r) => r.creationTime ? formatDateTime(new Date(r.creationTime)) : "", render: (r) => r.creationTime ? formatDateTime(new Date(r.creationTime)) : "—" },
              { header: "Accessed", csv: (r) => r.accessTime ? formatDateTime(new Date(r.accessTime)) : "", render: (r) => r.accessTime ? formatDateTime(new Date(r.accessTime)) : "—" },
              { header: "Volume Serial", wrap: true, csv: (r) => r.driveSerialNumber ?? r.netName ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.driveSerialNumber ?? r.netName ?? "—"}</span> },
              { header: "Machine ID", wrap: true, csv: (r) => r.machineId ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.machineId ?? "—"}</span> },
            ]}
          />
        )}

        {tab === "jumplist" && (
          <SimpleTable
            rows={jumpList}
            exportName={`windows-artifacts-${id}-jumplist`}
            empty="No Jump List entries — upload one or more .automaticDestinations-ms/.customDestinations-ms files to populate this tab."
            filter={{ label: "Source", getValue: (r) => r.source }}
            columns={[
              { header: "Target", wrap: true, csv: (r) => r.targetPath ?? "", render: (r) => <span className="font-mono text-xs">{r.targetPath ?? "—"}</span> },
              { header: "Source", csv: (r) => r.source, render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400 capitalize">{r.source}</span> },
              { header: "Source File", wrap: true, csv: (r) => fileNameById.get(r.fileId) ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{fileNameById.get(r.fileId) ?? "—"}</span> },
              { header: "App ID", wrap: true, csv: (r) => r.appId ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.appId ?? "—"}</span> },
              { header: "Last Accessed", csv: (r) => r.lastAccessed ? formatDateTime(new Date(r.lastAccessed)) : "", render: (r) => r.lastAccessed ? formatDateTime(new Date(r.lastAccessed)) : "—" },
              { header: "Rank", csv: (r) => String(r.accessRank ?? ""), render: (r) => r.accessRank ?? "—" },
              { header: "Pinned", csv: (r) => r.pinned === null ? "" : r.pinned ? "Yes" : "No", render: (r) => r.pinned === null ? "—" : r.pinned ? "Yes" : "No" },
            ]}
          />
        )}

        {tab === "shellbags" && (
          <SimpleTable
            rows={shellbags}
            exportName={`windows-artifacts-${id}-shellbags`}
            empty="No Shellbag entries — upload a UsrClass.dat to populate this tab."
            columns={[
              { header: "Path", wrap: true, csv: (r) => r.path, render: (r) => <span className="font-mono text-xs">{r.path}</span> },
              { header: "Type", csv: (r) => r.itemType ?? "", render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{r.itemType ?? "—"}</span> },
              { header: "Created", csv: (r) => r.creationTime ? formatDateTime(new Date(r.creationTime)) : "", render: (r) => r.creationTime ? formatDateTime(new Date(r.creationTime)) : "—" },
              { header: "Accessed", csv: (r) => r.accessTime ? formatDateTime(new Date(r.accessTime)) : "", render: (r) => r.accessTime ? formatDateTime(new Date(r.accessTime)) : "—" },
              { header: "Modified", csv: (r) => r.lastModified ? formatDateTime(new Date(r.lastModified)) : "", render: (r) => r.lastModified ? formatDateTime(new Date(r.lastModified)) : "—" },
            ]}
          />
        )}

        {tab === "mft" && (
          <SimpleTable
            rows={mft}
            exportName={`windows-artifacts-${id}-mft`}
            empty="No $MFT entries — upload a $MFT file to populate this tab."
            columns={[
              { header: "Name", wrap: true, csv: (r) => r.name, render: (r) => <span className="font-mono text-xs">{r.name}</span> },
              { header: "Path", wrap: true, csv: (r) => r.path ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.path ?? "—"}</span> },
              { header: "Allocated", csv: (r) => r.isAllocated ? "Yes" : "No", render: (r) => r.isAllocated ? "Yes" : <span className="text-red-400">No</span> },
              { header: "Directory", csv: (r) => r.isDirectory ? "Yes" : "No", render: (r) => r.isDirectory ? "Yes" : "No" },
              { header: "Created", csv: (r) => r.creationTime ? formatDateTime(new Date(r.creationTime)) : "", render: (r) => r.creationTime ? formatDateTime(new Date(r.creationTime)) : "—" },
              { header: "Entry Modified", csv: (r) => r.entryModificationTime ? formatDateTime(new Date(r.entryModificationTime)) : "", render: (r) => r.entryModificationTime ? formatDateTime(new Date(r.entryModificationTime)) : "—" },
              { header: "Size", csv: (r) => r.fileSize ?? "", render: (r) => r.fileSize ?? "—" },
              { header: "ADS", csv: (r) => r.hasAlternateDataStreams ? "Yes" : "No", render: (r) => r.hasAlternateDataStreams ? "Yes" : "No" },
            ]}
          />
        )}

        {tab === "usnjrnl" && (
          <SimpleTable
            rows={usnJrnl}
            exportName={`windows-artifacts-${id}-usnjrnl`}
            empty="No $UsnJrnl:$J entries — upload the $UsnJrnl:$J stream to populate this tab."
            columns={[
              { header: "Timestamp", csv: (r) => r.timestamp ? formatDateTime(new Date(r.timestamp)) : "", render: (r) => r.timestamp ? formatDateTime(new Date(r.timestamp)) : "—" },
              { header: "File Name", wrap: true, csv: (r) => r.fileName ?? "", render: (r) => <span className="font-mono text-xs">{r.fileName ?? "—"}</span> },
              { header: "Reason", wrap: true, csv: (r) => r.reason.join(" "), render: (r) => <span className="font-mono text-xs text-zinc-500">{r.reason.join(" ")}</span> },
              { header: "USN", csv: (r) => r.usn, render: (r) => <span className="font-mono text-xs text-zinc-500">{r.usn}</span> },
            ]}
          />
        )}

        {tab === "srum" && (
          <SimpleTable
            rows={srum}
            exportName={`windows-artifacts-${id}-srum`}
            empty="No SRUM entries — upload SRUDB.dat to populate this tab."
            filter={{ label: "Provider", getValue: (r) => r.providerLabel ?? r.tableName }}
            columns={[
              { header: "Timestamp", csv: (r) => r.timestamp ? formatDateTime(new Date(r.timestamp)) : "", render: (r) => r.timestamp ? formatDateTime(new Date(r.timestamp)) : "—" },
              { header: "Provider", wrap: true, csv: (r) => r.providerLabel ?? r.tableName, render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{r.providerLabel ?? r.tableName}</span> },
              { header: "App / SID", wrap: true, csv: (r) => r.appId ?? r.userSid ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.appId ?? r.userSid ?? "—"}</span> },
              { header: "Details", wrap: true, csv: (r) => JSON.stringify(r.details), render: (r) => <span className="font-mono text-xs text-zinc-500">{JSON.stringify(r.details)}</span> },
            ]}
          />
        )}

        {tab === "wer" && (
          <SimpleTable
            rows={werReports}
            exportName={`windows-artifacts-${id}-wer-reports`}
            empty="No WER reports — upload one or more Report.wer files to populate this tab."
            columns={[
              { header: "Event Type", csv: (r) => r.eventType ?? "", render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{r.eventType ?? "—"}</span> },
              { header: "App", wrap: true, csv: (r) => r.appName ?? "", render: (r) => <span className="font-mono text-xs">{r.appName ?? "—"}</span> },
              { header: "Fault Module", wrap: true, csv: (r) => r.faultModuleName ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.faultModuleName ?? "—"}</span> },
              { header: "Exception", csv: (r) => r.exceptionCode ?? "", render: (r) => <span className="font-mono text-xs text-red-400">{r.exceptionCode ?? "—"}</span> },
              { header: "Event Time", csv: (r) => r.eventTime ?? "", render: (r) => r.eventTime ? r.eventTime : "—" },
              { header: "Source File", wrap: true, csv: (r) => r.sourceFileName, render: (r) => <span className="font-mono text-xs text-zinc-500">{r.sourceFileName}</span> },
            ]}
          />
        )}

        {tab === "werdump" && (
          <SimpleTable
            rows={werDumps}
            exportName={`windows-artifacts-${id}-wer-dumps`}
            empty="No crash dumps — upload one or more .dmp files to populate this tab."
            columns={[
              { header: "Exception", csv: (r) => r.exceptionCode ?? "", render: (r) => <span className="font-mono text-xs text-red-400">{r.exceptionCode ?? "—"}</span> },
              { header: "Address", csv: (r) => r.exceptionAddress ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.exceptionAddress ?? "—"}</span> },
              { header: "PID", csv: (r) => String(r.processId ?? ""), render: (r) => r.processId ?? "—" },
              { header: "Process Created", csv: (r) => r.processCreateTime ?? "", render: (r) => r.processCreateTime ? formatDateTime(new Date(r.processCreateTime)) : "—" },
              { header: "OS Version", wrap: true, csv: (r) => r.osVersion ?? "", render: (r) => r.osVersion ?? "—" },
              { header: "Modules", csv: (r) => String(r.moduleList.length), render: (r) => <span className="text-xs text-zinc-500">{r.moduleList.length}</span> },
              { header: "Source File", wrap: true, csv: (r) => r.sourceFileName, render: (r) => <span className="font-mono text-xs text-zinc-500">{r.sourceFileName}</span> },
            ]}
          />
        )}

        {tab === "recyclebin" && (
          <SimpleTable
            rows={recycleBin}
            exportName={`windows-artifacts-${id}-recycle-bin`}
            empty="No Recycle Bin entries — upload one or more $I files to populate this tab."
            columns={[
              { header: "Original Path", wrap: true, csv: (r) => r.originalPath, render: (r) => <span className="font-mono text-xs">{r.originalPath}</span> },
              { header: "Deleted", csv: (r) => r.deletedTime ?? "", render: (r) => r.deletedTime ? formatDateTime(new Date(r.deletedTime)) : "—" },
              { header: "Size", csv: (r) => r.fileSizeBytes ?? "", render: (r) => r.fileSizeBytes ?? "—" },
              { header: "SID", wrap: true, csv: (r) => r.sid, render: (r) => <span className="font-mono text-xs text-zinc-500">{r.sid}</span> },
              { header: "Format", csv: (r) => String(r.formatVersion), render: (r) => `v${r.formatVersion}` },
            ]}
          />
        )}

        {tab === "notifications" && (
          <SimpleTable
            rows={notifications}
            exportName={`windows-artifacts-${id}-notifications`}
            empty="No notification entries — upload a wpndatabase.db/appdb.dat to populate this tab."
            columns={[
              { header: "Arrived", csv: (r) => r.arrivalTime ?? "", render: (r) => r.arrivalTime ? formatDateTime(new Date(r.arrivalTime)) : "—" },
              { header: "Handler", wrap: true, csv: (r) => r.handlerLabel ?? "", render: (r) => <span className="font-mono text-xs">{r.handlerLabel ?? "—"}</span> },
              { header: "Type", csv: (r) => r.notifType ?? "", render: (r) => r.notifType ?? "—" },
              { header: "Tag", wrap: true, csv: (r) => r.tag ?? "", render: (r) => <span className="text-xs text-zinc-500">{r.tag ?? "—"}</span> },
              { header: "Payload", wrap: true, csv: (r) => r.payload ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500 break-all">{r.payload ?? "—"}</span> },
              { header: "Profile", wrap: true, csv: (r) => r.profileName ?? "", render: (r) => r.profileName ?? "—" },
            ]}
          />
        )}

        {tab === "search" && (
          <SimpleTable
            rows={searchIndex}
            exportName={`windows-artifacts-${id}-search-index`}
            empty="No Windows Search entries — upload Windows.edb to populate this tab."
            filter={{ label: "Table", getValue: (r) => r.tableName }}
            columns={[
              { header: "Table", csv: (r) => r.tableName, render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{r.tableName}</span> },
              { header: "Record #", csv: (r) => String(r.recordIndex), render: (r) => r.recordIndex },
              { header: "Details", wrap: true, csv: (r) => JSON.stringify(r.details), render: (r) => <span className="font-mono text-xs text-zinc-500">{JSON.stringify(r.details)}</span> },
            ]}
          />
        )}

        {tab === "quarantine" && (
          <SimpleTable
            rows={quarantineEntries}
            exportName={`windows-artifacts-${id}-quarantine-entries`}
            empty="No Defender quarantine entries — upload one or more Quarantine\\Entries files to populate this tab."
            columns={[
              { header: "Detection", wrap: true, csv: (r) => r.detectionName ?? "", render: (r) => <span className="font-mono text-xs text-red-400">{r.detectionName ?? "—"}</span> },
              { header: "Detected", csv: (r) => r.timestamp ?? "", render: (r) => r.timestamp ? formatDateTime(new Date(r.timestamp)) : "—" },
              { header: "Resources", csv: (r) => String(r.resources.length), render: (r) => r.resources.length },
              { header: "Paths", wrap: true, csv: (r) => r.resources.map((x) => x.detection_path).filter(Boolean).join("; "), render: (r) => <span className="font-mono text-xs text-zinc-500 break-all">{r.resources.map((x) => x.detection_path).filter(Boolean).join("; ") || "—"}</span> },
              { header: "Source File", wrap: true, csv: (r) => r.sourceFileName, render: (r) => <span className="font-mono text-xs text-zinc-500">{r.sourceFileName}</span> },
            ]}
          />
        )}

        {tab === "quarantinepayloads" && (
          <div className="space-y-3">
            {quarantinePayloads.length === 0 ? (
              <p className="text-sm text-zinc-600 py-12 text-center rounded-xl border border-dashed border-zinc-800">
                No Defender quarantine payloads — upload one or more Quarantine\ResourceData files to populate this tab.
              </p>
            ) : (
              <>
                <p className="flex items-center gap-1.5 text-xs text-amber-500">
                  <AlertCircle className="h-3.5 w-3.5 shrink-0" />
                  Decrypted payloads are real (if previously quarantined) malware samples. Handle with care.
                </p>
                <SimpleTable
                  rows={quarantinePayloads}
                  exportName={`windows-artifacts-${id}-quarantine-payloads`}
                  empty=""
                  columns={[
                    { header: "Source File", wrap: true, csv: (r) => r.sourceFileName, render: (r) => <span className="font-mono text-xs">{r.sourceFileName}</span> },
                    { header: "SHA256", wrap: true, csv: (r) => r.sha256 ?? "", render: (r) => r.sha256 ? <Link href={`/intelligence/ioc/${encodeURIComponent(r.sha256)}`} className="font-mono text-xs text-amber-300 hover:underline">{r.sha256}</Link> : "—" },
                    { header: "Type", csv: (r) => r.fileTypeSniff ?? "", render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{r.fileTypeSniff ?? "—"}</span> },
                    { header: "Size", csv: (r) => r.decryptedSizeBytes ?? "", render: (r) => r.decryptedSizeBytes ?? "—" },
                    {
                      header: "Download", csv: () => "",
                      render: (r) => r.magicValid ? (
                        <a href={`/api/windows-artifacts/payloads/${r.id}/download`} className="flex items-center gap-1 text-xs text-amber-400 hover:underline">
                          <Download className="h-3 w-3" /> Decrypted
                        </a>
                      ) : <span className="text-xs text-zinc-600">—</span>,
                    },
                  ]}
                />
              </>
            )}
          </div>
        )}

        {tab === "bits" && (
          <SimpleTable
            rows={bitsJobs}
            exportName={`windows-artifacts-${id}-bits`}
            empty="No BITS job records — upload qmgr0.dat/qmgr1.dat to populate this tab."
            columns={[
              { header: "Name", wrap: true, csv: (r) => r.name ?? "", render: (r) => <span className="font-mono text-xs">{r.name ?? "—"}</span> },
              { header: "Destination", wrap: true, csv: (r) => r.destFn ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.destFn ?? "—"}</span> },
              { header: "Source", wrap: true, csv: (r) => r.srcFn ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500 break-all">{r.srcFn ?? "—"}</span> },
              { header: "State", csv: (r) => r.state ?? "", render: (r) => r.state ?? "—" },
              { header: "Created", csv: (r) => r.ctime ?? "", render: (r) => r.ctime ? formatDateTime(new Date(r.ctime)) : "—" },
              { header: "Carved", csv: (r) => r.isCarved ? "Yes" : "No", render: (r) => r.isCarved ? <span className="text-amber-400">Yes</span> : "No" },
            ]}
          />
        )}

        {tab === "timeline" && (
          <SimpleTable
            rows={timeline}
            exportName={`windows-artifacts-${id}-timeline`}
            empty="No Windows Timeline entries — upload one or more ActivitiesCache.db files to populate this tab."
            filter={{ label: "Kind", getValue: (r) => r.activityKind }}
            columns={[
              { header: "Start Time", csv: (r) => r.startTime ?? "", render: (r) => r.startTime ? formatDateTime(new Date(r.startTime)) : "—" },
              { header: "App / Package", wrap: true, csv: (r) => r.appDisplayName ?? r.packageIdentifier ?? "", render: (r) => <span className="font-mono text-xs">{r.appDisplayName ?? r.packageIdentifier ?? "—"}</span> },
              { header: "Description", wrap: true, csv: (r) => r.description ?? "", render: (r) => <span className="text-xs text-zinc-500">{r.description ?? "—"}</span> },
              { header: "Kind", csv: (r) => r.activityKind, render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{r.activityKind}</span> },
              { header: "Duration (s)", csv: (r) => String(r.activeDurationSeconds ?? ""), render: (r) => r.activeDurationSeconds ?? "—" },
              { header: "Profile", wrap: true, csv: (r) => r.profileName ?? "", render: (r) => r.profileName ?? "—" },
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
                  {f.matchedValue && <p className="mt-1 font-mono text-xs text-teal-400 break-all">{f.matchedValue}</p>}
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
  rows, columns, empty, exportName, filter,
}: {
  rows: T[];
  columns: { header: string; render: (row: T) => React.ReactNode; csv: (row: T) => string; wrap?: boolean }[];
  empty: string;
  exportName: string;
  filter?: { label: string; getValue: (row: T) => string };
}) {
  const [query, setQuery] = useState("");
  const [filterValue, setFilterValue] = useState("all");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;

  const filterOptions = useMemo(
    () => (filter ? Array.from(new Set(rows.map(filter.getValue))).sort((a, b) => a.localeCompare(b)) : []),
    [rows, filter]
  );

  const filtered = useMemo(() => {
    let r = rows;
    if (filter && filterValue !== "all") r = r.filter((row) => filter.getValue(row) === filterValue);
    const q = query.trim().toLowerCase();
    if (q) r = r.filter((row) => columns.some((c) => c.csv(row).toLowerCase().includes(q)));
    return r;
  }, [rows, query, filterValue, filter, columns]);

  useEffect(() => { setPage(1); }, [query, filterValue]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const paged = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  function exportCsv() {
    const lines = [
      columns.map((c) => csvEscape(c.header)).join(","),
      ...filtered.map((row) => columns.map((c) => csvEscape(c.csv(row))).join(",")),
    ];
    downloadBlob(`${exportName}.csv`, lines.join("\r\n"), "text/csv");
  }

  if (rows.length === 0) {
    return <p className="text-sm text-zinc-600 py-12 text-center rounded-xl border border-dashed border-zinc-800">{empty}</p>;
  }

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="flex min-w-[220px] flex-1 items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2">
          <Search className="h-3.5 w-3.5 shrink-0 text-zinc-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search this table…"
            className="flex-1 bg-transparent text-sm text-zinc-200 placeholder-zinc-600 outline-none"
          />
          {query && (
            <button onClick={() => setQuery("")} className="text-zinc-600 hover:text-zinc-300">&times;</button>
          )}
        </div>
        {filter && (
          <select
            value={filterValue}
            onChange={(e) => setFilterValue(e.target.value)}
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 outline-none"
          >
            <option value="all">All {filter.label}</option>
            {filterOptions.map((opt) => <option key={opt} value={opt}>{opt}</option>)}
          </select>
        )}
        <span className="text-xs text-zinc-500">
          {filtered.length === rows.length ? `${rows.length} rows` : `${filtered.length} of ${rows.length} rows`}
        </span>
        <button
          onClick={exportCsv}
          className="flex items-center gap-1.5 rounded-lg border border-zinc-700 px-3 py-2 text-xs font-medium text-zinc-300 hover:bg-zinc-800 transition-colors"
        >
          <Download className="h-3.5 w-3.5" /> Export CSV
        </button>
      </div>

      {filtered.length === 0 ? (
        <p className="text-sm text-zinc-600 py-12 text-center rounded-xl border border-dashed border-zinc-800">No rows match your search.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-950/80">
                {columns.map((c) => (
                  <th
                    key={c.header}
                    className={`px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500 ${c.wrap ? "" : "whitespace-nowrap"}`}
                  >
                    {c.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {paged.map((row) => (
                <tr key={row.id} className="border-b border-zinc-800/40 hover:bg-zinc-900/40">
                  {columns.map((c) => (
                    <td
                      key={c.header}
                      title={c.wrap ? c.csv(row) : undefined}
                      className={`px-4 py-2 align-top text-zinc-200 ${c.wrap ? "break-all" : "whitespace-nowrap"}`}
                    >
                      {c.render(row)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {filtered.length > PAGE_SIZE && (
        <div className="mt-3 flex items-center justify-between">
          <span className="text-xs text-zinc-500">
            Showing {(currentPage - 1) * PAGE_SIZE + 1}–{Math.min(currentPage * PAGE_SIZE, filtered.length)} of {filtered.length}
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40 transition-colors"
            >
              Previous
            </button>
            <span className="text-xs text-zinc-500">Page {currentPage} of {totalPages}</span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
