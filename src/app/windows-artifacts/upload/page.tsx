"use client";

import { useRef, useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, CheckCircle2, Folder, Clock,
  FileSearch, Plus, Search, Upload, X, File as FileIcon,
} from "lucide-react";
import { formatCaseNumber } from "@/lib/cases/case-number";

type CaseOption = { id: string; caseSeq: number; title: string; status: string; severity: string };
type Phase = "case" | "select" | "uploading" | "done" | "error";

const CASE_SEVERITIES = ["important", "notable", "interesting", "informational"];
const MAX_TOTAL_BYTES = 500 * 1024 * 1024;

type ProfileFile = { id: string; profileName: string; file: File | null };

function makeProfileFile(): ProfileFile {
  return { id: Math.random().toString(36).slice(2), profileName: "", file: null };
}

export default function UploadWindowsArtifactsPage() {
  const router = useRouter();

  // ── Case state ───────────────────────────────────────────────────────────
  const [cases, setCases] = useState<CaseOption[]>([]);
  const [selectedCase, setSelectedCase] = useState<CaseOption | null>(null);
  const [caseSearch, setCaseSearch] = useState("");
  const [showCreateCase, setShowCreateCase] = useState(false);
  const [newCaseTitle, setNewCaseTitle] = useState("");
  const [newCaseSeverity, setNewCaseSeverity] = useState("interesting");
  const [creatingCase, setCreatingCase] = useState(false);
  const [caseError, setCaseError] = useState("");

  // ── File state ───────────────────────────────────────────────────────────
  const [systemFile, setSystemFile] = useState<File | null>(null);
  const [softwareFile, setSoftwareFile] = useState<File | null>(null);
  const [securityFile, setSecurityFile] = useState<File | null>(null);
  const [amcacheFile, setAmcacheFile] = useState<File | null>(null);
  const [ntuserFiles, setNtuserFiles] = useState<ProfileFile[]>([makeProfileFile()]);
  const [usrclassFiles, setUsrclassFiles] = useState<ProfileFile[]>([]);
  const [prefetchFiles, setPrefetchFiles] = useState<File[]>([]);
  const [lnkFiles, setLnkFiles] = useState<File[]>([]);
  const [jumplistAutomaticFiles, setJumplistAutomaticFiles] = useState<File[]>([]);
  const [jumplistCustomFiles, setJumplistCustomFiles] = useState<File[]>([]);
  const [mftFile, setMftFile] = useState<File | null>(null);
  const [usnjrnlFile, setUsnjrnlFile] = useState<File | null>(null);
  const [usnJournalMetadataFile, setUsnJournalMetadataFile] = useState<File | null>(null);
  const [srudbFile, setSrudbFile] = useState<File | null>(null);
  const [hostname, setHostname] = useState("");
  const [notes, setNotes] = useState("");

  // ── Upload state ─────────────────────────────────────────────────────────
  const [phase, setPhase] = useState<Phase>("case");
  const [uploadPercent, setUploadPercent] = useState(0);
  const [resultId, setResultId] = useState("");
  const [error, setError] = useState("");

  const xhrRef = useRef<XMLHttpRequest | null>(null);

  useEffect(() => {
    fetch("/api/cases")
      .then(r => r.ok ? r.json() : { cases: [] })
      .then(d => setCases((d.cases ?? []).filter((c: { status: string }) => c.status !== "closed").map((c: { id: string; caseSeq: number; title: string; status: string; severity: string }) => ({
        id: c.id, caseSeq: c.caseSeq, title: c.title, status: c.status, severity: c.severity,
      }))));
  }, []);

  async function createAndSelectCase() {
    if (!newCaseTitle.trim()) { setCaseError("Case title is required."); return; }
    setCaseError("");
    setCreatingCase(true);
    try {
      const res = await fetch("/api/cases", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ title: newCaseTitle.trim(), severity: newCaseSeverity }),
      });
      const data = await res.json();
      if (!res.ok) { setCaseError(data.message ?? "Failed to create case."); return; }
      const newCase = data.case as CaseOption;
      setCases(prev => [newCase, ...prev]);
      selectCase(newCase);
    } catch {
      setCaseError("Network error. Please try again.");
    } finally {
      setCreatingCase(false);
    }
  }

  function selectCase(c: CaseOption) {
    setSelectedCase(c);
    setShowCreateCase(false);
    setPhase("select");
  }

  function reset() {
    setSystemFile(null); setSoftwareFile(null); setSecurityFile(null); setAmcacheFile(null);
    setNtuserFiles([makeProfileFile()]); setUsrclassFiles([]);
    setPrefetchFiles([]); setLnkFiles([]); setJumplistAutomaticFiles([]); setJumplistCustomFiles([]);
    setMftFile(null); setUsnjrnlFile(null); setUsnJournalMetadataFile(null); setSrudbFile(null);
    setHostname(""); setNotes(""); setError("");
    setSelectedCase(null); setPhase("case");
    setUploadPercent(0); setResultId("");
  }

  const totalBytes =
    (systemFile?.size ?? 0) + (softwareFile?.size ?? 0) + (securityFile?.size ?? 0) + (amcacheFile?.size ?? 0) +
    ntuserFiles.reduce((s, f) => s + (f.file?.size ?? 0), 0) +
    usrclassFiles.reduce((s, f) => s + (f.file?.size ?? 0), 0) +
    prefetchFiles.reduce((s, f) => s + f.size, 0) +
    lnkFiles.reduce((s, f) => s + f.size, 0) +
    jumplistAutomaticFiles.reduce((s, f) => s + f.size, 0) +
    jumplistCustomFiles.reduce((s, f) => s + f.size, 0) +
    (mftFile?.size ?? 0) + (usnjrnlFile?.size ?? 0) + (usnJournalMetadataFile?.size ?? 0) + (srudbFile?.size ?? 0);

  const hasAnyFile = !!(
    systemFile || softwareFile || securityFile || amcacheFile || ntuserFiles.some(f => f.file) || usrclassFiles.some(f => f.file) ||
    prefetchFiles.length > 0 || lnkFiles.length > 0 || jumplistAutomaticFiles.length > 0 || jumplistCustomFiles.length > 0 ||
    mftFile || usnjrnlFile || srudbFile
  );

  function handleSubmit() {
    if (!hasAnyFile || !selectedCase) return;
    if (totalBytes > MAX_TOTAL_BYTES) {
      setError(`Combined upload (${(totalBytes / 1024 / 1024).toFixed(0)} MB) exceeds the 500 MB limit for one collection.`);
      setPhase("error");
      return;
    }
    setPhase("uploading");
    setUploadPercent(0);
    setError("");

    const form = new FormData();
    form.append("caseId", selectedCase.id);
    if (hostname) form.append("hostname", hostname);
    if (notes) form.append("notes", notes);
    if (systemFile) form.append("system", systemFile);
    if (softwareFile) form.append("software", softwareFile);
    if (securityFile) form.append("security", securityFile);
    if (amcacheFile) form.append("amcache", amcacheFile);
    for (const f of ntuserFiles) {
      if (f.file) { form.append("ntuser", f.file); form.append("ntuserProfileName", f.profileName); }
    }
    for (const f of usrclassFiles) {
      if (f.file) { form.append("usrclass", f.file); form.append("usrclassProfileName", f.profileName); }
    }
    for (const f of prefetchFiles) {
      form.append("prefetch", f);
    }
    // A folder-picked file carries webkitRelativePath (e.g.
    // "FAVOUR/Desktop/foo.lnk") — sent alongside the file itself so the
    // server can keep that folder context instead of collapsing every
    // file down to its bare name (which also silently collides when two
    // different source folders happen to contain a same-named file).
    for (const f of lnkFiles) {
      form.append("lnk", f);
      form.append("lnkRelativePath", f.webkitRelativePath || f.name);
    }
    for (const f of jumplistAutomaticFiles) {
      form.append("jumplistAutomatic", f);
      form.append("jumplistAutomaticRelativePath", f.webkitRelativePath || f.name);
    }
    for (const f of jumplistCustomFiles) {
      form.append("jumplistCustom", f);
      form.append("jumplistCustomRelativePath", f.webkitRelativePath || f.name);
    }
    if (mftFile) form.append("mft", mftFile);
    if (usnjrnlFile) form.append("usnjrnl", usnjrnlFile);
    if (usnJournalMetadataFile) form.append("usnJournalMetadata", usnJournalMetadataFile);
    if (srudbFile) form.append("srudb", srudbFile);

    const xhr = new XMLHttpRequest();
    xhrRef.current = xhr;

    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) setUploadPercent(Math.round((e.loaded / e.total) * 100));
    });
    xhr.addEventListener("load", () => {
      try {
        const data = JSON.parse(xhr.responseText);
        if (xhr.status === 201 && data.upload) {
          setResultId(data.upload.id);
          setPhase("done");
        } else {
          setError(data.message ?? data.error ?? "Upload failed");
          setPhase("error");
        }
      } catch {
        setError("Unexpected server response. Please try again.");
        setPhase("error");
      }
    });
    xhr.addEventListener("error", () => {
      setError("Network error. Check your connection and try again.");
      setPhase("error");
    });
    xhr.addEventListener("abort", () => setPhase("select"));

    xhr.open("POST", "/api/windows-artifacts/uploads");
    xhr.send(form);
  }

  function handleCancel() { xhrRef.current?.abort(); }

  const filteredCases = cases.filter(c => {
    if (!caseSearch.trim()) return true;
    const q = caseSearch.toLowerCase();
    return c.title.toLowerCase().includes(q) || formatCaseNumber(c.caseSeq).toLowerCase().includes(q);
  });

  if (phase === "uploading") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="w-full max-w-sm text-center">
          <Upload className="mx-auto h-10 w-10 text-teal-400 mb-4" />
          <p className="text-zinc-300 font-medium">Uploading artifact collection…</p>
          <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-zinc-800">
            <div className="h-full rounded-full bg-teal-500 transition-all duration-200" style={{ width: `${uploadPercent}%` }} />
          </div>
          <p className="text-xs text-zinc-500 mt-2">{uploadPercent}%</p>
          <button onClick={handleCancel} className="mt-6 rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300">
            Cancel Upload
          </button>
        </div>
      </div>
    );
  }

  if (phase === "done") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <CheckCircle2 className="mx-auto h-10 w-10 text-teal-400 mb-4" />
          <p className="text-zinc-100 text-lg font-medium">Collection queued for analysis</p>
          <p className="text-sm text-zinc-400 mt-1 mb-1 flex items-center justify-center gap-1.5">
            <Clock className="h-3.5 w-3.5" /> Each file will be parsed independently in the background.
          </p>
          <div className="flex gap-3 justify-center mt-6">
            <button onClick={reset} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800">
              Upload another
            </button>
            <button onClick={() => router.push(`/windows-artifacts/${resultId}`)} className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500">
              View Status →
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto w-full max-w-4xl px-4 py-8 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3 text-sm text-zinc-400 mb-4">
            <Link href="/windows-artifacts" className="flex items-center gap-1.5 hover:text-zinc-200">
              <ArrowLeft className="h-3.5 w-3.5" /> Windows Artifacts
            </Link>
            <span>/</span>
            <span className="text-zinc-200">Upload Host Artifacts</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-teal-200 mb-2">
            <FileSearch className="h-4 w-4" />
            Windows Artifact Analysis
          </div>
          <h1 className="text-3xl font-semibold text-zinc-50">Upload Host Artifacts</h1>
          <p className="mt-2 text-sm text-zinc-400 max-w-xl">
            Upload whichever artifacts you collected from one host — registry hives, Prefetch, LNK files, Jump Lists,
            and more. Each file is parsed independently; you don&apos;t need all of them to get value from the ones you have.
          </p>
        </div>
      </section>

      <section className="mx-auto w-full max-w-4xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">

        {phase === "error" && (
          <div className="flex items-start gap-3 rounded-lg border border-red-900/50 bg-red-950/20 px-4 py-3 text-sm text-red-400">
            <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
            <span>{error}</span>
            <button onClick={() => setPhase("select")} className="ml-auto"><X className="h-4 w-4" /></button>
          </div>
        )}

        {/* Phase: case */}
        {phase === "case" && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6 shadow-sm space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-zinc-200 flex items-center gap-2 mb-1">
                <Folder className="h-4 w-4 text-teal-400" />
                Select Case
              </h2>
              <p className="text-xs text-zinc-500">Every artifact collection must belong to a case.</p>
            </div>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500 pointer-events-none" />
              <input type="text" value={caseSearch} onChange={e => setCaseSearch(e.target.value)}
                placeholder="Filter by case title or number…"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 pl-8 pr-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/20" />
            </div>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {filteredCases.length === 0 ? (
                <p className="text-sm text-zinc-600 py-6 text-center">
                  {caseSearch ? `No cases matching "${caseSearch}".` : "No cases yet. Create one below."}
                </p>
              ) : (
                filteredCases.map(c => (
                  <div key={c.id} className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2.5">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-zinc-500">{formatCaseNumber(c.caseSeq)}</span>
                        <span className="text-sm font-medium text-zinc-200 truncate">{c.title}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-xs text-zinc-500">{c.status}</span>
                        <span className="text-xs text-teal-500">· {c.severity}</span>
                      </div>
                    </div>
                    <button onClick={() => selectCase(c)} className="ml-4 shrink-0 rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-500 transition-colors">
                      Select
                    </button>
                  </div>
                ))
              )}
            </div>
            <div className="border-t border-zinc-800 pt-4">
              <button onClick={() => setShowCreateCase(v => !v)} className="flex items-center gap-1.5 text-sm text-teal-400 hover:text-teal-300">
                <Plus className="h-4 w-4" />
                {showCreateCase ? "Cancel" : "Create New Case"}
              </button>
              {showCreateCase && (
                <div className="mt-3 space-y-3 rounded-lg border border-zinc-700 bg-zinc-900 p-4">
                  {caseError && <p className="text-xs text-red-400 rounded bg-red-900/20 px-2 py-1.5">{caseError}</p>}
                  <div>
                    <label className="mb-1 block text-xs font-medium text-zinc-400">Title <span className="text-red-400">*</span></label>
                    <input value={newCaseTitle} onChange={e => setNewCaseTitle(e.target.value)} placeholder="Case title…"
                      className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500" />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs font-medium text-zinc-400">Severity</label>
                    <select value={newCaseSeverity} onChange={e => setNewCaseSeverity(e.target.value)}
                      className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 outline-none focus:border-teal-500">
                      {CASE_SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  <button onClick={createAndSelectCase} disabled={creatingCase || !newCaseTitle.trim()}
                    className="w-full rounded-md bg-teal-600 py-2 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                    {creatingCase ? "Creating…" : "Create & Select"}
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Phase: select */}
        {phase === "select" && selectedCase && (
          <div className="space-y-6">
            <CaseBanner selectedCase={selectedCase} onChangeCase={() => setPhase("case")} />

            <div>
              <h2 className="text-sm font-semibold text-zinc-300 mb-3">Registry Hives</h2>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <FileSlot label="SYSTEM" file={systemFile} onChange={setSystemFile} />
                <FileSlot label="SOFTWARE" file={softwareFile} onChange={setSoftwareFile} />
                <FileSlot label="SECURITY" file={securityFile} onChange={setSecurityFile} optionalNote="optional" />
                <FileSlot label="Amcache.hve" file={amcacheFile} onChange={setAmcacheFile} />
              </div>
            </div>

            <ProfileFileList
              title="NTUSER.DAT (one per user profile)"
              files={ntuserFiles}
              setFiles={setNtuserFiles}
              profilePlaceholder="e.g. jsmith"
            />

            <ProfileFileList
              title="UsrClass.dat (one per user profile — used by Shellbags)"
              files={usrclassFiles}
              setFiles={setUsrclassFiles}
              profilePlaceholder="e.g. jsmith"
            />

            <MultiFilePicker
              title="Prefetch (.pf files)"
              hint="select every .pf file from C:\Windows\Prefetch at once"
              accept=".pf"
              label=".pf file"
              files={prefetchFiles}
              setFiles={setPrefetchFiles}
            />

            <MultiFilePicker
              title="LNK Files (.lnk)"
              hint="individual shortcuts — spread across Desktop/Links/OneDrive/Recent Items; use &quot;Choose folder&quot; to grab them all at once"
              accept=".lnk"
              label=".lnk file"
              files={lnkFiles}
              setFiles={setLnkFiles}
              allowFolder
            />

            <MultiFilePicker
              title="Jump Lists — Automatic (.automaticDestinations-ms)"
              hint="from %AppData%\Roaming\Microsoft\Windows\Recent\AutomaticDestinations — one subfolder per user profile"
              accept=".automaticDestinations-ms"
              label="file"
              files={jumplistAutomaticFiles}
              setFiles={setJumplistAutomaticFiles}
              allowFolder
            />

            <MultiFilePicker
              title="Jump Lists — Custom (.customDestinations-ms)"
              hint="from %AppData%\Roaming\Microsoft\Windows\Recent\CustomDestinations — one subfolder per user profile"
              accept=".customDestinations-ms"
              label="file"
              files={jumplistCustomFiles}
              setFiles={setJumplistCustomFiles}
              allowFolder
            />

            <div>
              <h2 className="text-sm font-semibold text-zinc-300 mb-3">
                NTFS / SRUM Artifacts <span className="text-zinc-600 font-normal">(optional)</span>
              </h2>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <FileSlot label="$MFT" file={mftFile} onChange={setMftFile} optionalNote="Master File Table" />
                <FileSlot label="$J" file={usnjrnlFile} onChange={setUsnjrnlFile} optionalNote="the $UsnJrnl:$J stream" />
                <FileSlot label="UsnJournal_Metadata.txt" file={usnJournalMetadataFile} onChange={setUsnJournalMetadataFile} optionalNote="fsutil usn queryjournal output, if collected" />
                <FileSlot label="SRUDB.dat" file={srudbFile} onChange={setSrudbFile} optionalNote="SRUM database" />
              </div>
            </div>

            <div>
              <h2 className="text-sm font-semibold text-zinc-300 mb-3">
                Context <span className="text-zinc-600 font-normal">(optional)</span>
              </h2>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <label className="block text-xs text-zinc-400 mb-1.5">Hostname</label>
                  <input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="WIN-0SRSOE59SK1"
                    className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/20" />
                </div>
              </div>
              <div className="mt-4">
                <label className="block text-xs text-zinc-400 mb-1.5">Notes</label>
                <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={2}
                  placeholder="Any additional context about this collection…"
                  className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/20 resize-none" />
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-zinc-800 pt-6">
              <Link href="/windows-artifacts" className="text-sm text-zinc-500 hover:text-zinc-300">Cancel</Link>
              <button onClick={handleSubmit} disabled={!hasAnyFile}
                className="flex items-center gap-2 rounded-lg bg-teal-600 px-6 py-2.5 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50 transition-colors">
                <Upload className="h-4 w-4" />
                Upload &amp; Queue Analysis
              </button>
            </div>
          </div>
        )}

      </section>
    </div>
  );
}

function MultiFilePicker({
  title, hint, accept, label, files, setFiles, allowFolder,
}: {
  title: string;
  hint: string;
  accept: string;
  label: string;
  files: File[];
  setFiles: (files: File[]) => void;
  /** Collector output for this artifact type can be spread across several
   * subfolders (e.g. LNK files under Desktop/Links/OneDrive, or Jump Lists
   * under one subfolder per user profile) — a plain multi-select file
   * picker can only grab files from one folder per dialog. When set, this
   * adds a second "Choose folder…" picker that recursively collects every
   * matching file from a chosen folder and its subfolders in one action. */
  allowFolder?: boolean;
}) {
  const acceptExts = accept.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  function filterByAccept(list: File[]): File[] {
    if (acceptExts.length === 0) return list;
    return list.filter((f) => acceptExts.some((ext) => f.name.toLowerCase().endsWith(ext)));
  }

  return (
    <div>
      <h2 className="text-sm font-semibold text-zinc-300 mb-3">
        {title} <span className="text-zinc-600 font-normal">(optional — {hint})</span>
      </h2>
      <div className="flex flex-col gap-2 sm:flex-row">
        <label className="flex flex-1 items-center gap-3 rounded-lg border border-dashed border-zinc-700 px-3 py-2.5 text-sm text-zinc-400 hover:border-teal-600 hover:text-teal-400 cursor-pointer">
          <FileIcon className="h-4 w-4 shrink-0" />
          <span className="flex-1 min-w-0 truncate">
            {files.length > 0 ? `${files.length} ${label}${files.length === 1 ? "" : "s"} selected` : `Choose ${label}s…`}
          </span>
          {files.length > 0 && (
            <button type="button" onClick={(e) => { e.preventDefault(); setFiles([]); }} className="shrink-0 text-zinc-600 hover:text-red-400">
              <X className="h-3.5 w-3.5" />
            </button>
          )}
          <input type="file" multiple accept={accept} className="hidden"
            onChange={(e) => setFiles(filterByAccept(Array.from(e.target.files ?? [])))} />
        </label>
        {allowFolder && (
          <label
            title="Recursively collects every matching file from the chosen folder and its subfolders"
            className="flex items-center justify-center gap-2 rounded-lg border border-dashed border-zinc-700 px-3 py-2.5 text-sm text-zinc-400 hover:border-teal-600 hover:text-teal-400 cursor-pointer sm:w-44"
          >
            <Folder className="h-4 w-4 shrink-0" />
            <span>Choose folder…</span>
            <input
              type="file"
              multiple
              className="hidden"
              ref={(el) => {
                // webkitdirectory/directory aren't part of React's typed
                // input props — set directly so TypeScript doesn't need a
                // cast, and the directory-picking behavior still applies.
                if (el) { el.setAttribute("webkitdirectory", ""); el.setAttribute("directory", ""); }
              }}
              onChange={(e) => setFiles(filterByAccept(Array.from(e.target.files ?? [])))}
            />
          </label>
        )}
      </div>
    </div>
  );
}

function FileSlot({ label, file, onChange, optionalNote }: { label: string; file: File | null; onChange: (f: File | null) => void; optionalNote?: string }) {
  return (
    <label className="flex items-center gap-3 rounded-lg border border-dashed border-zinc-700 px-3 py-2.5 text-sm text-zinc-400 hover:border-teal-600 hover:text-teal-400 cursor-pointer">
      <FileIcon className="h-4 w-4 shrink-0" />
      <span className="flex-1 min-w-0 truncate">
        {file ? file.name : <>{label} {optionalNote && <span className="text-zinc-600">({optionalNote})</span>}</>}
      </span>
      {file && (
        <button type="button" onClick={(e) => { e.preventDefault(); onChange(null); }} className="shrink-0 text-zinc-600 hover:text-red-400">
          <X className="h-3.5 w-3.5" />
        </button>
      )}
      <input type="file" className="hidden" onChange={(e) => onChange(e.target.files?.[0] ?? null)} />
    </label>
  );
}

function ProfileFileList({
  title, files, setFiles, profilePlaceholder,
}: {
  title: string;
  files: ProfileFile[];
  setFiles: (updater: (prev: ProfileFile[]) => ProfileFile[]) => void;
  profilePlaceholder: string;
}) {
  return (
    <div>
      <h2 className="text-sm font-semibold text-zinc-300 mb-3">{title}</h2>
      <div className="space-y-2">
        {files.map((pf) => (
          <div key={pf.id} className="flex items-center gap-2">
            <input
              value={pf.profileName}
              onChange={(e) => setFiles((prev) => prev.map((f) => f.id === pf.id ? { ...f, profileName: e.target.value } : f))}
              placeholder={profilePlaceholder}
              className="w-40 shrink-0 rounded-md border border-zinc-700 bg-zinc-800 px-2.5 py-2 text-xs text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
            />
            <div className="flex-1">
              <FileSlot label="Choose file…" file={pf.file} onChange={(f) => setFiles((prev) => prev.map((x) => x.id === pf.id ? { ...x, file: f } : x))} />
            </div>
            <button
              type="button"
              onClick={() => setFiles((prev) => prev.length > 1 ? prev.filter((f) => f.id !== pf.id) : prev)}
              className="shrink-0 p-2 text-zinc-600 hover:text-red-400"
              title="Remove"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
      </div>
      <button
        type="button"
        onClick={() => setFiles((prev) => [...prev, makeProfileFile()])}
        className="mt-2 flex items-center gap-1.5 text-xs text-teal-400 hover:text-teal-300"
      >
        <Plus className="h-3.5 w-3.5" /> Add another profile
      </button>
    </div>
  );
}

function CaseBanner({ selectedCase, onChangeCase }: { selectedCase: CaseOption | null; onChangeCase?: () => void }) {
  if (!selectedCase) return null;
  return (
    <div className="flex items-center justify-between rounded-lg border border-teal-500/30 bg-teal-500/5 px-3 py-2">
      <div className="text-sm">
        <span className="text-zinc-400">Case: </span>
        <span className="font-mono text-xs text-zinc-500 mr-1">{formatCaseNumber(selectedCase.caseSeq)}</span>
        <span className="font-medium text-teal-400">{selectedCase.title}</span>
      </div>
      {onChangeCase && (
        <button onClick={onChangeCase} className="text-xs text-zinc-500 hover:text-zinc-300">Change</button>
      )}
    </div>
  );
}
