"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, CheckCircle2, Clock, Loader2, FileSearch, RefreshCw, Search, Download,
} from "lucide-react";
import { CaseBadge } from "@/components/cases/case-badge";
import { ArchiveButton, ArchivedPill } from "@/components/cases/archive-button";
import { formatDateTime } from "@/lib/utils";
import { PLATFORM_LABEL, uploadPlatform } from "@/lib/windows-artifacts/types";

type FileRow = {
  id: string; role: string; filename: string; status: string; errorMessage: string | null; findingCount: number; profileName: string | null;
  provenance: string | null; integrityStatus: string | null; manifestSha256: string | null; sha256: string;
};
type ManifestIssue = { status: string; label: string; sourcePath: string; destinationPath: string; sizeBytes: number | null; duplicateOf: string | null; note: string | null; timestampUtc: string | null };
type CollectionManifest = {
  totalRecords: number; statusCounts: Record<string, number>; collectionStartUtc: string | null; collectionEndUtc: string | null;
  issues: ManifestIssue[]; issuesTruncated: boolean;
};
type Upload = {
  id: string; hostname: string | null; notes: string | null; findingCount: number; createdAt: string;
  collectionManifest: CollectionManifest | null;
  uploadedBy: { email: string; name: string | null } | null;
  case: { id: string; title: string; caseSeq: number; status: string; archivedAt: string | null } | null;
  archivedAt: string | null;
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
type ArtifactRecord = {
  id: string; fileId: string; kind: string; title: string; timestamp: string | null; path: string | null;
  userName: string | null; process: string | null; url: string | null; ip: string | null;
  sha256: string | null; sha1: string | null; md5: string | null; details: Record<string, unknown>;
};
type RegistryPluginRow = { id: string; fileId: string; plugin: string; keyPath: string | null; timestamp: string | null; summary: string; details: Record<string, unknown> };
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
  registryPlugins: RegistryPluginRow[];
  artifactRecords: ArtifactRecord[];
  /** Total rows per record kind — artifactRecords is capped per kind. */
  artifactRecordCounts?: Record<string, number>;
  findings: Finding[];
};

type Tab = "overview" | "shimcache" | "amcache" | "userassist" | "bam" | "autoruns" | "prefetch" | "lnk" | "jumplist" | "shellbags" | "mft" | "usnjrnl" | "srum"
  | "wer" | "werdump" | "recyclebin" | "notifications" | "search" | "quarantine" | "quarantinepayloads" | "bits" | "timeline"
  | "accounts" | "registryplugins" | "rec_wmi" | "rec_defender" | "rec_apps" | "rec_other" | "integrity" | "findings"
  | "lx_accounts" | "lx_logins" | "lx_history" | "lx_ssh" | "lx_persistence" | "lx_processes" | "lx_timeline" | "lx_system"
  | "mc_accounts" | "mc_persistence" | "mc_history" | "mc_ssh" | "mc_processes" | "mc_signing" | "mc_privacy" | "mc_activity" | "mc_timeline" | "mc_system";

// Stage-2 record kinds grouped into tabs (see forensicator_records.py),
// and every Linux (linux-parse.py) and macOS (mac-parse.py) collector kind —
// a tab with a `platform` is the only kind a collection from that platform
// shows besides Overview/Integrity/Findings.
const RECORD_TABS: { key: Tab; label: string; match: (kind: string) => boolean; empty: string; platform?: "linux" | "macos" }[] = [
  { key: "lx_accounts", platform: "linux", label: "Accounts & Privilege", match: (k) => /^linux_(account|shadow|group|sudoers)$/.test(k), empty: "No passwd/shadow/group/sudoers in this collection." },
  { key: "lx_logins", platform: "linux", label: "Logins", match: (k) => /^linux_(login|failed_login|login_event)$/.test(k), empty: "No wtmp/btmp/utmp records — the authentication log went to Log Analysis." },
  { key: "lx_history", platform: "linux", label: "Shell History", match: (k) => k === "linux_shell_history", empty: "No shell or application history files." },
  { key: "lx_ssh", platform: "linux", label: "SSH", match: (k) => k.startsWith("linux_ssh_"), empty: "No authorized_keys or known_hosts files." },
  { key: "lx_persistence", platform: "linux", label: "Persistence", match: (k) => /^linux_(cron_job|cron_script|systemd_unit|systemd_generator|config_line|immutable_file|symlink)$/.test(k), empty: "No cron, systemd, startup or other persistence files." },
  { key: "lx_processes", platform: "linux", label: "Processes & Network", match: (k) => /^linux_(process|recovered_executable|socket|container|bpf_program)$/.test(k), empty: "No process table or socket list." },
  { key: "lx_timeline", platform: "linux", label: "Filesystem Timeline", match: (k) => k === "linux_fs_entry", empty: "No bodyfile in this collection." },
  { key: "lx_system", platform: "linux", label: "System State", match: (k) => /^linux_(package|kernel_|cmd_)/.test(k), empty: "No system state output." },
  { key: "mc_accounts", platform: "macos", label: "Accounts & Privilege", match: (k) => /^mac_(account|group|sudoers|auth_mechanism)$/.test(k), empty: "No account records, sudoers or login authorization rule — run the collector as root." },
  { key: "mc_persistence", platform: "macos", label: "Persistence", match: (k) => /^mac_(launch_item|background_item|cron_job|cron_script|config_line|plist_entry)$/.test(k), empty: "No launch items, login items, cron, startup or other persistence files." },
  { key: "mc_history", platform: "macos", label: "Shell History", match: (k) => k === "mac_shell_history", empty: "No shell or Terminal session history files." },
  { key: "mc_ssh", platform: "macos", label: "SSH", match: (k) => k.startsWith("mac_ssh_"), empty: "No authorized_keys or known_hosts files." },
  { key: "mc_processes", platform: "macos", label: "Processes & Network", match: (k) => /^mac_(process|socket|proxy)$/.test(k), empty: "No process table or socket list." },
  { key: "mc_signing", platform: "macos", label: "Code Signing & Apps", match: (k) => /^mac_(code_signature|application)$/.test(k), empty: "No code signature or application list." },
  { key: "mc_privacy", platform: "macos", label: "Privacy & Downloads", match: (k) => /^mac_(tcc_grant|quarantine_event)$/.test(k), empty: "No TCC or quarantine databases — the collector needs a terminal with Full Disk Access." },
  { key: "mc_activity", platform: "macos", label: "App Usage & Installs", match: (k) => /^mac_(app_usage|install)$/.test(k), empty: "No KnowledgeC or install history in this collection." },
  { key: "mc_timeline", platform: "macos", label: "Filesystem Timeline", match: (k) => /^mac_(fs_entry|fsevent)$/.test(k), empty: "No bodyfile or FSEvents in this collection." },
  { key: "mc_system", platform: "macos", label: "System State", match: (k) => /^mac_(security_setting|kext|xprotect_event|os_version|cmd_)/.test(k), empty: "No system state output." },
  { key: "rec_wmi", label: "WMI Persistence", match: (k) => k.startsWith("wmi_"), empty: "No WMI subscription data — upload WMI\\PermanentSubscriptions.json (and optionally WMI\\Repository\\OBJECTS.DATA)." },
  { key: "rec_defender", label: "Defender History", match: (k) => k.startsWith("defender_"), empty: "No Defender history — upload Defender\\DetectionHistory and Defender\\Support logs." },
  { key: "rec_apps", label: "Application Artifacts", match: (k) => /^(remote_access|notepad|cloud_sync|security_product|custom)_/.test(k), empty: "No application artifacts — upload the collector's ApplicationArtifacts folder." },
  { key: "rec_other", label: "NTFS, Payloads & Extras", match: (k) => /^(logfile_|recycle_payload|memory_|log4j_|gpo_report|ram_|clipboard_)/.test(k), empty: "No $LogFile, Recycle Bin payload, memory-file, LOG4J, GPResult or RAM-extra records in this collection." },
];

// Plugin rows shown on the Accounts tab rather than the generic Registry
// Plugins tab — see registry-parse.py's run_sam()/run_security().
const ACCOUNT_PLUGINS = new Set(["samparse", "forensicator_sam_group_membership", "forensicator_lsa_secret", "forensicator_cached_logon", "local_sid", "domain_sid"]);

const INTEGRITY_BADGE: Record<string, { label: string; className: string }> = {
  verified:        { label: "hash verified", className: "border-teal-800 bg-teal-900/30 text-teal-400" },
  mismatch:        { label: "HASH MISMATCH", className: "border-red-900 bg-red-900/40 text-red-400" },
  not_in_manifest: { label: "not in manifest", className: "border-zinc-700 bg-zinc-800 text-zinc-400" },
};

function fmt(ts: string | null | undefined): string {
  return ts ? formatDateTime(new Date(ts)) : "";
}

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
    const res = await fetch(`/api/host-artifacts/uploads/${id}`);
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
    timeline, registryPlugins, artifactRecords, findings,
  } = data;
  const platform = uploadPlatform(upload.files.map((f) => f.role));
  const recordCount = (match: (kind: string) => boolean) => data.artifactRecordCounts
    ? Object.entries(data.artifactRecordCounts).reduce((n, [k, c]) => (match(k) ? n + c : n), 0)
    : artifactRecords.filter((r) => match(r.kind)).length;

  // filename carries the source subfolder when the upload form's folder
  // picker was used (e.g. "FAVOUR/Desktop/foo.lnk") — surfaced as a Source
  // column below so LNK/Jump List entries stay traceable to which
  // Desktop/Links/OneDrive/profile folder they actually came from.
  const fileNameById = new Map(upload.files.map((f) => [f.id, f.filename]));
  // "Source" column for hive/NTFS-derived tabs: a collection can hold the
  // live SYSTEM hive next to RegBack/Windows.old/restore-point copies, or
  // several volumes' $MFT — provenance says which one a row came from.
  const sourceById = new Map(upload.files.map((f) => [f.id, f.provenance && f.provenance !== "live" ? `${f.provenance} · ${f.filename}` : f.filename]));
  const sourceColumn = <T extends { fileId: string }>() => ({
    header: "Source", wrap: true,
    csv: (r: T) => sourceById.get(r.fileId) ?? "",
    render: (r: T) => <span className="font-mono text-xs text-zinc-500">{sourceById.get(r.fileId) ?? "—"}</span>,
  });

  const accountRows = registryPlugins.filter((r) => ACCOUNT_PLUGINS.has(r.plugin));
  const otherPluginRows = registryPlugins.filter((r) => !ACCOUNT_PLUGINS.has(r.plugin));
  const samAccounts = accountRows.filter((r) => r.plugin === "samparse");
  const groupMembers = accountRows.filter((r) => r.plugin === "forensicator_sam_group_membership");
  const lsaSecrets = accountRows.filter((r) => r.plugin === "forensicator_lsa_secret");
  const cachedLogons = accountRows.filter((r) => r.plugin === "forensicator_cached_logon" && r.details.populated === true);
  const adminSids = new Set(groupMembers.filter((g) => g.details.group_rid === 544).map((g) => String(g.details.member_sid ?? "")));
  const isAdmin = (rid: unknown) => [...adminSids].some((sid) => sid.endsWith(`-${String(rid)}`));
  const integrityCounts = upload.files.reduce<Record<string, number>>((acc, f) => {
    if (f.integrityStatus) acc[f.integrityStatus] = (acc[f.integrityStatus] ?? 0) + 1;
    return acc;
  }, {});
  const mismatchCount = integrityCounts.mismatch ?? 0;

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
    { key: "accounts", label: "Accounts & Secrets", count: samAccounts.length + lsaSecrets.length + cachedLogons.length },
    { key: "registryplugins", label: "Registry Plugins", count: otherPluginRows.length },
    ...RECORD_TABS.map((t) => ({ key: t.key, label: t.label, count: recordCount(t.match) })),
    { key: "integrity", label: mismatchCount > 0 ? "Collection Integrity ⚠" : "Collection Integrity", count: upload.collectionManifest?.issues.length ?? 0 },
    { key: "findings", label: "Findings", count: findings.length },
  ];
  // Each platform's collection has only its own artifact types.
  const ALWAYS_SHOWN: Tab[] = ["overview", "integrity", "findings"];
  const tabPlatform = new Map<Tab, string>(RECORD_TABS.filter((t) => t.platform).map((t) => [t.key, t.platform!]));
  const visibleTabs = TABS.filter((t) => ALWAYS_SHOWN.includes(t.key) || (tabPlatform.get(t.key) ?? "windows") === platform);

  return (
    <div className="min-h-screen">
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto w-full max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
          <Link href="/host-artifacts" className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300 mb-4">
            <ArrowLeft className="h-4 w-4" /> Host Artifacts
          </Link>
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-sm text-teal-200 mb-1">
                <FileSearch className="h-4 w-4" /> Host Artifact Analysis
              </div>
              <h1 className="text-2xl font-semibold text-zinc-50 flex items-center gap-2">
                {upload.hostname ?? "(unnamed host)"}
                <span className="rounded-full border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-xs font-medium text-zinc-300">{PLATFORM_LABEL[platform]}</span>
              </h1>
              {upload.case && <div className="mt-1 text-sm"><CaseBadge kase={upload.case} showTitle /></div>}
              {/* Only an upload with no case is archived on its own — one in a case goes with its case. */}
              {!upload.case && (
                <div className="mt-2 flex items-center gap-2">
                  {upload.archivedAt && <ArchivedPill />}
                  <ArchiveButton type="windows-artifacts" id={upload.id} action={upload.archivedAt ? "restore" : "archive"} onDone={() => load()} />
                </div>
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
          {visibleTabs.map((t) => (
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
                    {f.provenance && f.provenance !== "live" && (
                      <span className="rounded border border-amber-900 bg-amber-900/20 px-1.5 py-0.5 text-[10px] text-amber-400">{f.provenance}</span>
                    )}
                    {f.integrityStatus && INTEGRITY_BADGE[f.integrityStatus] && (
                      <span className={`rounded border px-1.5 py-0.5 text-[10px] ${INTEGRITY_BADGE[f.integrityStatus].className}`}>{INTEGRITY_BADGE[f.integrityStatus].label}</span>
                    )}
                  </div>
                  <span className="text-xs text-zinc-500 capitalize">{f.status}</span>
                </div>
                {f.errorMessage && (
                  // On a ready file this is a parse caveat (warning), not a failure.
                  <p className={`mt-2 text-xs ${f.status === "failed" ? "text-red-400" : "text-amber-400"}`}>{f.errorMessage}</p>
                )}
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
              sourceColumn(),
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
              sourceColumn(),
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
              sourceColumn(),
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
              sourceColumn(),
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
              sourceColumn(),
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
              sourceColumn(),
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
                        <a href={`/api/host-artifacts/payloads/${r.id}/download`} className="flex items-center gap-1 text-xs text-amber-400 hover:underline">
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

        {tab === "accounts" && (
          <div className="space-y-8">
            <section>
              <h3 className="mb-2 text-sm font-semibold text-zinc-300">Local accounts (SAM)</h3>
              <SimpleTable
                rows={samAccounts}
                exportName={`windows-artifacts-${id}-sam-accounts`}
                empty="No SAM accounts — upload the SAM hive to populate this table."
                columns={[
                  { header: "Account", csv: (r) => String(r.details.username ?? ""), render: (r) => <span className="font-mono text-xs">{String(r.details.username ?? "—")}</span> },
                  { header: "RID", csv: (r) => String(r.details.rid ?? ""), render: (r) => String(r.details.rid ?? "—") },
                  { header: "Admin", csv: (r) => isAdmin(r.details.rid) ? "Yes" : "No", render: (r) => isAdmin(r.details.rid) ? <span className="text-amber-400">Yes</span> : "No" },
                  { header: "Logons", csv: (r) => String(r.details.login_count ?? ""), render: (r) => String(r.details.login_count ?? "—") },
                  { header: "Last Logon", csv: (r) => fmt(r.details.last_login as string | null), render: (r) => fmt(r.details.last_login as string | null) || "—" },
                  { header: "Password Set", csv: (r) => fmt(r.details.password_last_set as string | null), render: (r) => fmt(r.details.password_last_set as string | null) || "—" },
                  { header: "Failed Logons", csv: (r) => String(r.details.failed_login_count ?? ""), render: (r) => String(r.details.failed_login_count ?? "—") },
                  { header: "Flags", wrap: true, csv: (r) => ((r.details.account_flags_parsed as string[] | undefined) ?? []).join(", "), render: (r) => <span className="text-xs text-zinc-500">{((r.details.account_flags_parsed as string[] | undefined) ?? []).join(", ") || "—"}</span> },
                  sourceColumn<RegistryPluginRow>(),
                ]}
              />
            </section>
            <section>
              <h3 className="mb-2 text-sm font-semibold text-zinc-300">Local group membership</h3>
              <SimpleTable
                rows={groupMembers}
                exportName={`windows-artifacts-${id}-sam-groups`}
                empty="No group membership — upload the SAM hive to populate this table."
                filter={{ label: "Groups", getValue: (r) => String(r.details.group_name ?? "") }}
                columns={[
                  { header: "Group", csv: (r) => String(r.details.group_name ?? ""), render: (r) => <span className={r.details.group_rid === 544 ? "text-amber-400" : ""}>{String(r.details.group_name ?? "—")}</span> },
                  { header: "Member", wrap: true, csv: (r) => String(r.details.member_name ?? ""), render: (r) => <span className="font-mono text-xs">{String(r.details.member_name ?? "—")}</span> },
                  { header: "Member SID", wrap: true, csv: (r) => String(r.details.member_sid ?? ""), render: (r) => <span className="font-mono text-xs text-zinc-500">{String(r.details.member_sid ?? "—")}</span> },
                  sourceColumn<RegistryPluginRow>(),
                ]}
              />
            </section>
            <section>
              <h3 className="mb-2 text-sm font-semibold text-zinc-300">LSA secrets <span className="font-normal text-zinc-600">(names only — values are not decrypted)</span></h3>
              <SimpleTable
                rows={lsaSecrets}
                exportName={`windows-artifacts-${id}-lsa-secrets`}
                empty="No LSA secrets — upload the SECURITY hive to populate this table."
                columns={[
                  { header: "Secret", wrap: true, csv: (r) => String(r.details.secret_name ?? ""), render: (r) => <span className="font-mono text-xs">{String(r.details.secret_name ?? "—")}</span> },
                  { header: "Meaning", wrap: true, csv: (r) => String(r.details.meaning ?? ""), render: (r) => <span className="text-xs text-zinc-400">{String(r.details.meaning ?? "—")}</span> },
                  { header: "Last Updated", csv: (r) => fmt(r.details.last_updated as string | null), render: (r) => fmt(r.details.last_updated as string | null) || "—" },
                  sourceColumn<RegistryPluginRow>(),
                ]}
              />
            </section>
            <section>
              <h3 className="mb-2 text-sm font-semibold text-zinc-300">Cached domain logons <span className="font-normal text-zinc-600">(populated NL$ slots)</span></h3>
              <SimpleTable
                rows={cachedLogons}
                exportName={`windows-artifacts-${id}-cached-logons`}
                empty="No populated cached-logon slots in the uploaded SECURITY hive(s)."
                columns={[
                  { header: "Slot", csv: (r) => String(r.details.slot ?? ""), render: (r) => <span className="font-mono text-xs">{String(r.details.slot ?? "—")}</span> },
                  { header: "User RID", csv: (r) => String(r.details.user_rid ?? ""), render: (r) => String(r.details.user_rid ?? "—") },
                  { header: "Last Cached Logon", csv: (r) => fmt(r.details.last_cached_logon as string | null), render: (r) => fmt(r.details.last_cached_logon as string | null) || "—" },
                  sourceColumn<RegistryPluginRow>(),
                ]}
              />
            </section>
          </div>
        )}

        {tab === "registryplugins" && (
          <SimpleTable
            rows={otherPluginRows}
            exportName={`windows-artifacts-${id}-registry-plugins`}
            empty="No registry plugin results — upload SYSTEM/SOFTWARE/NTUSER.DAT/DEFAULT hives to populate this tab."
            filter={{ label: "Plugins", getValue: (r) => r.plugin }}
            columns={[
              { header: "Plugin", csv: (r) => r.plugin, render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{r.plugin}</span> },
              { header: "Key", wrap: true, csv: (r) => r.keyPath ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.keyPath ?? "—"}</span> },
              { header: "Data", wrap: true, csv: (r) => r.summary, render: (r) => <span className="font-mono text-xs">{r.summary || JSON.stringify(r.details).slice(0, 400)}</span> },
              { header: "Timestamp", csv: (r) => fmt(r.timestamp), render: (r) => fmt(r.timestamp) || "—" },
              sourceColumn<RegistryPluginRow>(),
            ]}
          />
        )}

        {RECORD_TABS.filter((t) => t.key === tab).map((t) => recordCount(t.match) > artifactRecords.filter((r) => t.match(r.kind)).length && (
          <p key={`${t.key}-cap`} className="mb-2 text-xs text-zinc-500">
            Showing {artifactRecords.filter((r) => t.match(r.kind)).length.toLocaleString()} of {recordCount(t.match).toLocaleString()} records (flagged ones first) — every record went through the detection rules.
          </p>
        ))}
        {RECORD_TABS.filter((t) => t.key === tab).map((t) => (
          <SimpleTable
            key={t.key}
            rows={artifactRecords.filter((r) => t.match(r.kind))}
            exportName={`windows-artifacts-${id}-${t.key.replace("rec_", "")}`}
            empty={t.empty}
            filter={{ label: "Types", getValue: (r) => r.kind }}
            columns={[
              { header: "Type", csv: (r) => r.kind, render: (r) => <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{r.kind}</span> },
              ...(t.platform ? [{
                header: "Flags", wrap: true, csv: (r: ArtifactRecord) => String(r.details?.findings ?? ""),
                render: (r: ArtifactRecord) => {
                  const flags = String(r.details?.findings ?? "").split(",").filter(Boolean);
                  return flags.length ? (
                    <div className="flex flex-wrap gap-1">{flags.map((f) => <span key={f} className="rounded border border-amber-800/60 bg-amber-900/20 px-1.5 py-0.5 text-[10px] text-amber-300">{f.replace(/_/g, " ")}</span>)}</div>
                  ) : <span className="text-xs text-zinc-700">—</span>;
                },
              }] : []),
              { header: "Time", csv: (r) => fmt(r.timestamp), render: (r) => fmt(r.timestamp) || "—" },
              {
                header: "Event", wrap: true, csv: (r) => r.title,
                render: (r) => (
                  <details>
                    <summary className="cursor-pointer text-xs">{r.title}</summary>
                    <pre className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap rounded bg-zinc-950 p-2 text-[11px] text-zinc-400">{JSON.stringify(r.details, null, 2)}</pre>
                  </details>
                ),
              },
              { header: "Path / URL", wrap: true, csv: (r) => r.path ?? r.url ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.path ?? r.url ?? "—"}</span> },
              { header: "User / Process", wrap: true, csv: (r) => [r.userName, r.process].filter(Boolean).join(" / "), render: (r) => <span className="text-xs text-zinc-500">{[r.userName, r.process].filter(Boolean).join(" / ") || "—"}</span> },
              { header: "IP", csv: (r) => r.ip ?? "", render: (r) => <span className="font-mono text-xs text-zinc-500">{r.ip ?? "—"}</span> },
              { header: "Hash", wrap: true, csv: (r) => r.sha256 ?? r.sha1 ?? r.md5 ?? "", render: (r) => (r.sha256 ?? r.sha1) ? <Link href={`/intelligence/ioc/${encodeURIComponent((r.sha256 ?? r.sha1)!)}`} className="font-mono text-xs text-amber-300 hover:underline">{r.sha256 ?? r.sha1}</Link> : <span className="font-mono text-xs text-zinc-600">{r.md5 ?? "—"}</span> },
              sourceColumn<ArtifactRecord>(),
            ]}
          />
        ))}

        {tab === "integrity" && (
          <div className="space-y-6">
            {!upload.collectionManifest && upload.files.every((f) => !f.integrityStatus) ? (
              <p className="text-sm text-zinc-600 py-12 text-center rounded-xl border border-dashed border-zinc-800">
                No CollectionManifest was uploaded with this collection — upload the collector folder (which includes it) to verify hashes and see acquisition gaps.
              </p>
            ) : (
              <>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  {[
                    { label: "Hash verified", value: integrityCounts.verified ?? 0, className: "text-teal-400" },
                    { label: "Hash mismatch", value: mismatchCount, className: mismatchCount > 0 ? "text-red-400" : "text-zinc-300" },
                    { label: "Not in manifest", value: integrityCounts.not_in_manifest ?? 0, className: "text-zinc-300" },
                    { label: "Manifest records", value: upload.collectionManifest?.totalRecords ?? 0, className: "text-zinc-300" },
                  ].map((c) => (
                    <div key={c.label} className="rounded-xl border border-zinc-800 bg-zinc-900 p-3">
                      <div className={`text-xl font-semibold ${c.className}`}>{c.value}</div>
                      <div className="text-xs text-zinc-500">{c.label}</div>
                    </div>
                  ))}
                </div>
                {upload.collectionManifest && (
                  <p className="text-xs text-zinc-500">
                    Collector status counts: {Object.entries(upload.collectionManifest.statusCounts).map(([k, v]) => `${k} ${v}`).join(" · ")}
                    {upload.collectionManifest.collectionStartUtc && ` — acquired ${fmt(upload.collectionManifest.collectionStartUtc)} to ${fmt(upload.collectionManifest.collectionEndUtc)}`}
                  </p>
                )}
                {mismatchCount > 0 && (
                  <div className="space-y-2">
                    <h3 className="text-sm font-semibold text-red-400">Files whose hash differs from the collector&apos;s manifest</h3>
                    {upload.files.filter((f) => f.integrityStatus === "mismatch").map((f) => (
                      <div key={f.id} className="rounded-lg border border-red-900/50 bg-red-950/20 p-3 font-mono text-xs">
                        <div className="text-zinc-200">{f.filename}</div>
                        <div className="text-zinc-500">manifest {f.manifestSha256}</div>
                        <div className="text-zinc-500">received {f.sha256.toUpperCase()}</div>
                      </div>
                    ))}
                  </div>
                )}
                {upload.collectionManifest && (
                  <section>
                    <h3 className="mb-2 text-sm font-semibold text-zinc-300">
                      Acquisition gaps and notes <span className="font-normal text-zinc-600">(every manifest record other than Collected{upload.collectionManifest.issuesTruncated ? " — truncated" : ""})</span>
                    </h3>
                    <SimpleTable
                      rows={upload.collectionManifest.issues.map((r, i) => ({ ...r, id: String(i) }))}
                      exportName={`windows-artifacts-${id}-collection-gaps`}
                      empty="The collector recorded no skipped, failed, or deduplicated artifacts."
                      filter={{ label: "Statuses", getValue: (r) => r.status }}
                      columns={[
                        { header: "Status", csv: (r) => r.status, render: (r) => <span className={`rounded px-1.5 py-0.5 text-xs ${r.status === "Failed" || r.status === "IntegrityMismatch" ? "bg-red-900/40 text-red-400" : "bg-zinc-800 text-zinc-400"}`}>{r.status}</span> },
                        { header: "Artifact", wrap: true, csv: (r) => r.label, render: (r) => <span className="text-xs">{r.label}</span> },
                        { header: "Path", wrap: true, csv: (r) => r.destinationPath, render: (r) => <span className="font-mono text-xs text-zinc-500">{r.destinationPath}</span> },
                        { header: "Note", wrap: true, csv: (r) => r.note ?? (r.duplicateOf ? `duplicate of ${r.duplicateOf}` : ""), render: (r) => <span className="text-xs text-zinc-400">{r.note ?? (r.duplicateOf ? `duplicate of ${r.duplicateOf}` : "—")}</span> },
                      ]}
                    />
                  </section>
                )}
              </>
            )}
          </div>
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
