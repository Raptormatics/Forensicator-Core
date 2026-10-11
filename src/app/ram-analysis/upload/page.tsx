"use client";

import { useRef, useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, CheckCircle2, Folder, Clock,
  MemoryStick, Plus, Search, Upload, X,
} from "lucide-react";
import { UploadDropzone, SelectedFileCard, type ValidatedFile } from "@/components/uploads/UploadDropzone";
import { formatCaseNumber } from "@/lib/cases/case-number";

type CaseOption = {
  id: string;
  caseSeq: number;
  title: string;
  status: string;
  severity: string;
};

type Phase = "case" | "select" | "details" | "uploading" | "done" | "error";

const CASE_SEVERITIES = ["important", "notable", "interesting", "informational"];
const MAX_RAM_BYTES = 64 * 1024 * 1024 * 1024; // 64 GB — matches the server's default cap

type OsType = "windows" | "linux" | "macos";

const OS_OPTIONS: { value: OsType; label: string; extensions: string[]; note?: string }[] = [
  { value: "windows", label: "Windows", extensions: [".raw", ".dmp", ".vmem"] },
  { value: "linux",   label: "Linux",   extensions: [".lime", ".lime.compressed"] },
  {
    value: "macos", label: "macOS", extensions: [".lime.compressed"],
    note: "Only the avml-fallback .lime.compressed format is supported — osxpmem's .aff4 output isn't (Volatility3 has no AFF4 support).",
  },
];

export default function UploadRamPage() {
  const router = useRouter();

  // ── Case state ───────────────────────────────────────────────────────────
  const [cases, setCases]               = useState<CaseOption[]>([]);
  const [selectedCase, setSelectedCase] = useState<CaseOption | null>(null);
  const [caseSearch, setCaseSearch]     = useState("");
  const [showCreateCase, setShowCreateCase] = useState(false);
  const [newCaseTitle, setNewCaseTitle]       = useState("");
  const [newCaseSeverity, setNewCaseSeverity] = useState("interesting");
  const [creatingCase, setCreatingCase] = useState(false);
  const [caseError, setCaseError]       = useState("");

  // ── File + form state ────────────────────────────────────────────────────
  const [osType, setOsType]       = useState<OsType>("windows");
  const [validated, setValidated] = useState<ValidatedFile | null>(null);
  const [hostname, setHostname]   = useState("");
  const [assetName, setAssetName] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [notes, setNotes]         = useState("");

  // ── Upload state ─────────────────────────────────────────────────────────
  const [phase, setPhase]                 = useState<Phase>("case");
  const [uploadPercent, setUploadPercent] = useState(0);
  const [resultId, setResultId]           = useState("");
  const [error, setError]                 = useState("");

  const xhrRef = useRef<XMLHttpRequest | null>(null);
  const sessionIdRef = useRef<string | null>(null);
  const cancelledRef = useRef(false);

  useEffect(() => {
    fetch("/api/cases")
      .then(r => r.ok ? r.json() : { cases: [] })
      // Closed cases can't accept new uploads — don't offer them here.
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

  function handleFileSelected(v: ValidatedFile) {
    setValidated(v);
    if (!v.error) setPhase("details");
  }

  function handleClear() {
    setValidated(null);
    setPhase("select");
  }

  function reset() {
    setValidated(null); setHostname(""); setAssetName("");
    setIpAddress(""); setNotes(""); setError(""); setOsType("windows");
    setSelectedCase(null); setPhase("case");
    setUploadPercent(0); setResultId("");
  }

  // Uploads in chunks well under any fronting reverse proxy/tunnel's own
  // body-size cap (e.g. Cloudflare's, enforced at its edge — no
  // origin-server config can raise it) instead of one giant POST. See
  // src/app/api/ram-analysis/uploads/chunked/**.
  type ChunkResult = { receivedBytes: string; totalBytes: string };
  type ChunkFailure =
    | { type: "offset_mismatch"; expectedOffset: string }
    | { type: "aborted" }
    | { type: "http_error"; message?: string };

  function putChunk(sessionId: string, offset: number, blob: Blob, onProgress: (loaded: number) => void): Promise<ChunkResult> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhrRef.current = xhr;
      xhr.upload.addEventListener("progress", (e) => {
        if (e.lengthComputable) onProgress(e.loaded);
      });
      xhr.addEventListener("load", () => {
        let data: Record<string, unknown> | null = null;
        try { data = JSON.parse(xhr.responseText); } catch { /* handled below */ }
        if (xhr.status === 200 && data && typeof data.receivedBytes === "string") {
          resolve(data as unknown as ChunkResult);
        } else if (xhr.status === 409 && data && typeof data.expectedOffset === "string") {
          reject({ type: "offset_mismatch", expectedOffset: data.expectedOffset } satisfies ChunkFailure);
        } else {
          reject({ type: "http_error", message: typeof data?.message === "string" ? data.message : undefined } satisfies ChunkFailure);
        }
      });
      xhr.addEventListener("error", () => reject({ type: "http_error" } satisfies ChunkFailure));
      xhr.addEventListener("abort", () => reject({ type: "aborted" } satisfies ChunkFailure));
      xhr.open("PUT", `/api/ram-analysis/uploads/chunked/${sessionId}/chunk?offset=${offset}`);
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.send(blob);
    });
  }

  async function handleSubmit() {
    if (!validated?.file || validated.error || !selectedCase) return;
    const file = validated.file;
    cancelledRef.current = false;
    setPhase("uploading");
    setUploadPercent(0);
    setError("");

    try {
      const initRes = await fetch("/api/ram-analysis/uploads/chunked/init", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          osType, caseId: selectedCase.id, filename: file.name, totalBytes: file.size,
          hostname: hostname || undefined, assetName: assetName || undefined,
          ipAddress: ipAddress || undefined, notes: notes || undefined,
        }),
      });
      const initData = await initRes.json().catch(() => null);
      if (!initRes.ok || typeof initData?.sessionId !== "string") {
        setError(initData?.message ?? "Failed to start upload.");
        setPhase("error");
        return;
      }
      const sessionId: string = initData.sessionId;
      const chunkSize: number = initData.chunkSize;
      sessionIdRef.current = sessionId;

      let offset = 0;
      while (offset < file.size) {
        if (cancelledRef.current) return;
        const chunkStartOffset = offset;
        const blob = file.slice(chunkStartOffset, Math.min(chunkStartOffset + chunkSize, file.size));

        let attempt = 0;
        let advanced = false;
        while (!advanced) {
          attempt++;
          try {
            const result = await putChunk(sessionId, chunkStartOffset, blob, (loaded) => {
              setUploadPercent(Math.round(((chunkStartOffset + loaded) / file.size) * 100));
            });
            offset = Number(result.receivedBytes);
            advanced = true;
          } catch (err) {
            if (cancelledRef.current) return;
            const failure = err as ChunkFailure;
            if (failure.type === "aborted") return;
            if (failure.type === "offset_mismatch") {
              // Server already has bytes up to a different point than we
              // thought (e.g. this exact chunk succeeded once already but
              // we never saw the response) — trust it and reslice from
              // there rather than treating this as a failed attempt.
              offset = Number(failure.expectedOffset);
              break;
            }
            if (attempt >= 5) {
              setError(failure.message ?? "Upload failed after several retries. Check your connection and try again.");
              setPhase("error");
              return;
            }
            await new Promise((r) => setTimeout(r, Math.min(1000 * attempt, 5000)));
          }
        }
      }

      const completeRes = await fetch(`/api/ram-analysis/uploads/chunked/${sessionId}/complete`, { method: "POST" });
      const completeData = await completeRes.json().catch(() => null);
      if (completeRes.ok && completeData?.upload) {
        setResultId(completeData.upload.id);
        setPhase("done");
      } else {
        setError(completeData?.message ?? "Failed to finalize upload.");
        setPhase("error");
      }
    } catch {
      setError("Network error. Check your connection and try again.");
      setPhase("error");
    }
  }

  function handleCancel() {
    cancelledRef.current = true;
    xhrRef.current?.abort();
    const sessionId = sessionIdRef.current;
    if (sessionId) {
      fetch(`/api/ram-analysis/uploads/chunked/${sessionId}`, { method: "DELETE" }).catch(() => {});
    }
    setPhase("details");
  }

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
          <p className="text-zinc-300 font-medium">Uploading {validated?.file.name}…</p>
          <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-zinc-800">
            <div className="h-full rounded-full bg-teal-500 transition-all duration-200" style={{ width: `${uploadPercent}%` }} />
          </div>
          <p className="text-xs text-zinc-500 mt-2">{uploadPercent}%</p>
          <p className="text-xs text-zinc-600 mt-4">Large memory images can take a while to upload — keep this tab open.</p>
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
          <p className="text-zinc-100 text-lg font-medium">Memory image queued for analysis</p>
          <p className="text-sm text-zinc-400 mt-1 mb-1 flex items-center justify-center gap-1.5">
            <Clock className="h-3.5 w-3.5" /> {validated?.file.name} will be parsed in the background.
          </p>
          <p className="text-xs text-zinc-600 mb-6">Volatility3 analysis can take anywhere from minutes to over an hour depending on image size.</p>
          <div className="flex gap-3 justify-center">
            <button onClick={reset} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800">
              Upload another
            </button>
            <button onClick={() => router.push(`/ram-analysis/${resultId}`)} className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500">
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
            <Link href="/ram-analysis" className="flex items-center gap-1.5 hover:text-zinc-200">
              <ArrowLeft className="h-3.5 w-3.5" /> RAM Analysis
            </Link>
            <span>/</span>
            <span className="text-zinc-200">Upload Memory Image</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-teal-200 mb-2">
            <MemoryStick className="h-4 w-4" />
            Forensicator Enterprise
          </div>
          <h1 className="text-3xl font-semibold text-zinc-50">Upload Memory Image</h1>
          <p className="mt-2 text-sm text-zinc-400 max-w-xl">
            Upload a Windows, Linux, or macOS memory image. Forensicator will extract processes, network connections, and injected-code findings, and run detection rules in the background. Linux/macOS need a matching Volatility3 symbol table uploaded first.
          </p>
        </div>
      </section>

      <section className="mx-auto w-full max-w-4xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">

        {phase === "error" && (
          <div className="flex items-start gap-3 rounded-lg border border-red-900/50 bg-red-950/20 px-4 py-3 text-sm text-red-400">
            <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
            <span>{error}</span>
            <button onClick={() => setPhase("details")} className="ml-auto"><X className="h-4 w-4" /></button>
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
              <p className="text-xs text-zinc-500">Every RAM upload must belong to a case.</p>
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
        {phase === "select" && (
          <div className="space-y-6">
            <CaseBanner selectedCase={selectedCase} onChangeCase={() => { setPhase("case"); setValidated(null); }} />

            <div>
              <h2 className="text-sm font-semibold text-zinc-300 mb-3">Operating System</h2>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                {OS_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setOsType(opt.value)}
                    className={`rounded-lg border px-4 py-3 text-left transition-colors ${
                      osType === opt.value
                        ? "border-teal-500 bg-teal-900/20 ring-1 ring-teal-500/30"
                        : "border-zinc-700 bg-zinc-800/50 hover:border-zinc-600 hover:bg-zinc-800"
                    }`}
                  >
                    <p className="text-sm font-medium text-zinc-200">{opt.label}</p>
                    <p className="text-xs text-zinc-500 mt-0.5">{opt.extensions.join(", ")}</p>
                  </button>
                ))}
              </div>
              {OS_OPTIONS.find((o) => o.value === osType)?.note && (
                <p className="mt-2 text-xs text-yellow-500/80">{OS_OPTIONS.find((o) => o.value === osType)?.note}</p>
              )}
              {osType !== "windows" && (
                <p className="mt-2 text-xs text-zinc-500">
                  Needs a matching Volatility3 symbol table —{" "}
                  <Link href="/ram-analysis/symbols" className="text-teal-400 hover:text-teal-300">manage Symbol Tables →</Link>
                </p>
              )}
            </div>

            <UploadDropzone
              key={osType}
              onFile={handleFileSelected}
              extensions={OS_OPTIONS.find((o) => o.value === osType)!.extensions}
              accept={{ "application/octet-stream": OS_OPTIONS.find((o) => o.value === osType)!.extensions }}
              maxSizeBytes={MAX_RAM_BYTES}
              fileKindLabel="memory image"
            />
          </div>
        )}

        {/* Phase: details */}
        {phase === "details" && validated && (
          <div className="space-y-8">
            <CaseBanner selectedCase={selectedCase} />
            <SelectedFileCard file={validated.file} error={validated.error} onClear={handleClear} />

            {!validated.error && (
              <>
                <div>
                  <h2 className="text-sm font-semibold text-zinc-300 mb-3">
                    Context <span className="text-zinc-600 font-normal">(optional)</span>
                  </h2>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                    {[
                      { label: "Hostname",   value: hostname,  setter: setHostname,  placeholder: "server01.internal" },
                      { label: "Asset Name", value: assetName, setter: setAssetName, placeholder: "Web Server - Prod" },
                      { label: "IP Address", value: ipAddress, setter: setIpAddress, placeholder: "10.0.0.1" },
                    ].map(({ label, value, setter, placeholder }) => (
                      <div key={label}>
                        <label className="block text-xs text-zinc-400 mb-1.5">{label}</label>
                        <input value={value} onChange={(e) => setter(e.target.value)} placeholder={placeholder}
                          className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/20" />
                      </div>
                    ))}
                  </div>
                  <div className="mt-4">
                    <label className="block text-xs text-zinc-400 mb-1.5">Notes</label>
                    <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={2}
                      placeholder="Any additional context about this memory image…"
                      className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/20 resize-none" />
                  </div>
                </div>
                <div className="flex items-center justify-between border-t border-zinc-800 pt-6">
                  <Link href="/ram-analysis" className="text-sm text-zinc-500 hover:text-zinc-300">Cancel</Link>
                  <button onClick={handleSubmit}
                    className="flex items-center gap-2 rounded-lg bg-teal-600 px-6 py-2.5 text-sm font-medium text-white hover:bg-teal-500 transition-colors">
                    <Upload className="h-4 w-4" />
                    Upload &amp; Queue Analysis
                  </button>
                </div>
              </>
            )}
            {validated.error && (
              <button onClick={handleClear} className="w-full rounded-lg border border-zinc-700 px-4 py-2.5 text-sm text-zinc-400 hover:bg-zinc-800">
                Choose a different file
              </button>
            )}
          </div>
        )}

      </section>
    </div>
  );
}

function CaseBanner({
  selectedCase,
  onChangeCase,
}: {
  selectedCase: CaseOption | null;
  onChangeCase?: () => void;
}) {
  if (!selectedCase) return null;
  return (
    <div className="flex items-center justify-between rounded-lg border border-teal-500/30 bg-teal-500/5 px-3 py-2">
      <div className="text-sm">
        <span className="text-zinc-400">Case: </span>
        <span className="font-mono text-xs text-zinc-500 mr-1">{formatCaseNumber(selectedCase.caseSeq)}</span>
        <span className="font-medium text-teal-400">{selectedCase.title}</span>
      </div>
      {onChangeCase && (
        <button onClick={onChangeCase} className="text-xs text-zinc-500 hover:text-zinc-300">
          Change
        </button>
      )}
    </div>
  );
}
