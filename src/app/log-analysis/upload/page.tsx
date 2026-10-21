"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useDropzone } from "react-dropzone";
import {
  AlertCircle, ArrowLeft, CheckCircle2, ChevronDown, ChevronRight,
  Folder, FileText, Loader2, Plus, ScrollText, Search, Upload, X
} from "lucide-react";
import Link from "next/link";
import { formatCaseNumber } from "@/lib/cases/case-number";

type DecoderOption = {
  id: string;
  name: string;
  title: string | null;
  description: string | null;
  isBuiltin: boolean;
  enabled: boolean;
};

type CaseOption = {
  id: string;
  caseSeq: number;
  title: string;
  status: string;
  severity: string;
};

type Phase = "case" | "upload" | "uploading" | "done" | "error";

const ACCEPTED_EXTS = [".log", ".txt", ".csv", ".json", ".ndjson", ".gz", ".evtx"];
const CASE_SEVERITIES = ["important", "notable", "interesting", "informational"];

/** Extract vendor label from decoder name e.g. decoder/apache-access/0 → Apache */
function extractVendor(name: string): string {
  const mid    = name.split("/")[1] ?? name;
  const vendor = mid.split("-")[0] ?? mid;
  return vendor.charAt(0).toUpperCase() + vendor.slice(1);
}

export default function UploadLogPage() {
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

  // ── Upload form state ────────────────────────────────────────────────────
  const [phase, setPhase]           = useState<Phase>("case");
  const [file, setFile]             = useState<File | null>(null);
  const fileIsEvtx = !!file && file.name.toLowerCase().endsWith(".evtx");
  const [sourceType, setSourceType] = useState<string>("");
  const [hostname, setHostname]     = useState("");
  const [assetName, setAssetName]   = useState("");
  const [ipAddress, setIpAddress]   = useState("");
  const [notes, setNotes]           = useState("");
  const [error, setError]           = useState("");
  const [resultId, setResultId]     = useState("");
  const [decoders, setDecoders]     = useState<DecoderOption[]>([]);
  const [loadingDecoders, setLoadingDecoders] = useState(true);
  const [expandedVendors, setExpandedVendors] = useState<Set<string>>(new Set());

  /** Builtin decoders grouped by vendor, sorted alphabetically */
  const vendorGroups = useMemo(() => {
    const groups: Record<string, DecoderOption[]> = {};
    for (const d of decoders.filter((d) => d.isBuiltin && d.enabled)) {
      const v = extractVendor(d.name);
      (groups[v] ??= []).push(d);
    }
    return Object.entries(groups).sort(([a], [b]) => a.localeCompare(b));
  }, [decoders]);

  const customDecoders = useMemo(
    () => decoders.filter((d) => !d.isBuiltin && d.enabled),
    [decoders],
  );

  function toggleVendor(vendor: string) {
    setExpandedVendors((prev) => {
      const next = new Set(prev);
      next.has(vendor) ? next.delete(vendor) : next.add(vendor);
      return next;
    });
  }

  useEffect(() => {
    fetch("/api/cases")
      .then(r => r.ok ? r.json() : { cases: [] })
      // Closed cases can't accept new uploads — don't offer them here.
      .then(d => setCases((d.cases ?? []).filter((c: { status: string }) => c.status !== "closed").map((c: { id: string; caseSeq: number; title: string; status: string; severity: string }) => ({
        id: c.id, caseSeq: c.caseSeq, title: c.title, status: c.status, severity: c.severity,
      }))));
    fetch("/api/log-analysis/decoders")
      .then((r) => r.json())
      .then((data) => {
        const all: DecoderOption[] = data.decoders ?? [];
        setDecoders(all);
      })
      .catch(() => setDecoders([]))
      .finally(() => setLoadingDecoders(false));
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
    setPhase("upload");
  }

  const onDrop = useCallback((accepted: File[]) => {
    if (accepted[0]) setFile(accepted[0]);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { "text/*": ACCEPTED_EXTS, "application/json": [".json", ".ndjson"], "application/gzip": [".gz"], "application/octet-stream": [".evtx"] },
    multiple: false,
    // 256 MB is the raw .evtx limit; the server enforces 50 MB for text logs.
    maxSize: 256 * 1024 * 1024,
  });

  async function handleSubmit() {
    if (!file || (!sourceType && !fileIsEvtx) || !selectedCase) return;
    setPhase("uploading");
    setError("");
    try {
      const form = new FormData();
      form.append("file", file);
      // Raw .evtx is converted to Event XML server-side and always decoded
      // as windows-event, whatever decoder is (or isn't) selected.
      form.append("sourceType", sourceType || "windows-event");
      form.append("caseId", selectedCase.id);
      if (hostname) form.append("hostname", hostname);
      if (assetName) form.append("assetName", assetName);
      if (ipAddress) form.append("ipAddress", ipAddress);
      if (notes) form.append("notes", notes);

      const res = await fetch("/api/log-analysis/uploads", { method: "POST", body: form });
      const data = await res.json();

      if (!res.ok) {
        setError(data.message ?? data.error ?? "Upload failed");
        setPhase("error");
        return;
      }
      setResultId(data.upload?.id ?? "");
      setPhase("done");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
      setPhase("error");
    }
  }

  function reset() {
    setFile(null); setSourceType(""); setHostname(""); setAssetName("");
    setIpAddress(""); setNotes(""); setError("");
    setSelectedCase(null); setPhase("case");
  }

  const filteredCases = cases.filter(c => {
    if (!caseSearch.trim()) return true;
    const q = caseSearch.toLowerCase();
    return c.title.toLowerCase().includes(q) || formatCaseNumber(c.caseSeq).toLowerCase().includes(q);
  });

  const canSubmit = !!file && (!!sourceType || fileIsEvtx) && phase === "upload";

  if (phase === "uploading") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <Loader2 className="mx-auto h-10 w-10 animate-spin text-teal-400 mb-4" />
          <p className="text-zinc-300 font-medium">Parsing and analyzing your log file…</p>
          <p className="text-sm text-zinc-500 mt-1">Normalizing events and extracting IOCs</p>
        </div>
      </div>
    );
  }

  if (phase === "done") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <CheckCircle2 className="mx-auto h-10 w-10 text-teal-400 mb-4" />
          <p className="text-zinc-100 text-lg font-medium">Analysis complete!</p>
          <p className="text-sm text-zinc-400 mt-1 mb-6">{file?.name} has been processed successfully.</p>
          <div className="flex gap-3 justify-center">
            <button onClick={reset} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800">
              Upload another
            </button>
            <button onClick={() => router.push(`/log-analysis/${resultId}`)} className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500">
              View Results →
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
            <Link href="/log-analysis" className="flex items-center gap-1.5 hover:text-zinc-200">
              <ArrowLeft className="h-3.5 w-3.5" /> Log Analysis
            </Link>
            <span>/</span>
            <span className="text-zinc-200">Upload Log</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-teal-200 mb-2">
            <ScrollText className="h-4 w-4" />
            Forensicator Enterprise
          </div>
          <h1 className="text-3xl font-semibold text-zinc-50">Upload Log File</h1>
          <p className="mt-2 text-sm text-zinc-400 max-w-xl">
            Select your log file and source application. Forensicator will normalize events, extract IOCs, and run your detection rules automatically.
          </p>
        </div>
      </section>

      <section className="mx-auto w-full max-w-4xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">

        {phase === "error" && (
          <div className="flex items-start gap-3 rounded-lg border border-red-900/50 bg-red-950/20 px-4 py-3 text-sm text-red-400">
            <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
            <span>{error}</span>
            <button onClick={reset} className="ml-auto"><X className="h-4 w-4" /></button>
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
              <p className="text-xs text-zinc-500">Every log upload must belong to a case.</p>
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

        {/* Phase: upload */}
        {phase === "upload" && (
          <div className="space-y-8">
            <div className="flex items-center justify-between rounded-lg border border-teal-500/30 bg-teal-500/5 px-3 py-2">
              <div className="text-sm">
                <span className="text-zinc-400">Case: </span>
                <span className="font-mono text-xs text-zinc-500 mr-1">{selectedCase && formatCaseNumber(selectedCase.caseSeq)}</span>
                <span className="font-medium text-teal-400">{selectedCase?.title}</span>
              </div>
              <button onClick={() => setPhase("case")} className="text-xs text-zinc-500 hover:text-zinc-300">Change</button>
            </div>

            <div>
              <h2 className="text-sm font-semibold text-zinc-300 mb-3 flex items-center gap-2">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-teal-900 text-xs text-teal-300">1</span>
                Select Log File
              </h2>
              <div
                {...getRootProps()}
                className={`relative flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed px-6 py-12 cursor-pointer transition-colors ${
                  isDragActive ? "border-teal-500 bg-teal-900/10" : file ? "border-teal-700 bg-teal-950/20" : "border-zinc-700 bg-zinc-900/30 hover:border-zinc-600"
                }`}
              >
                <input {...getInputProps()} />
                {file ? (
                  <>
                    <FileText className="h-10 w-10 text-teal-400" />
                    <div className="text-center">
                      <p className="text-zinc-200 font-medium">{file.name}</p>
                      <p className="text-sm text-zinc-500 mt-0.5">
                        {(file.size / 1024).toFixed(0)} KB
                        {file.size > 10 * 1024 * 1024 && <span className="ml-2 text-yellow-400">Large file — parsing may take a moment</span>}
                      </p>
                    </div>
                    <button onClick={(e) => { e.stopPropagation(); setFile(null); }} className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-red-400 mt-1">
                      <X className="h-3 w-3" /> Remove
                    </button>
                  </>
                ) : (
                  <>
                    <Upload className="h-10 w-10 text-zinc-500" />
                    <div className="text-center">
                      <p className="text-zinc-300 font-medium">{isDragActive ? "Drop your log file here" : "Drag & drop your log file"}</p>
                      <p className="text-sm text-zinc-600 mt-1">or click to browse</p>
                      <p className="text-xs text-zinc-700 mt-2">{ACCEPTED_EXTS.join("  ")} · max 50 MB (256 MB for raw .evtx)</p>
                    </div>
                  </>
                )}
              </div>
            </div>

            <div>
              <h2 className="text-sm font-semibold text-zinc-300 mb-3 flex items-center gap-2">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-teal-900 text-xs text-teal-300">2</span>
                Select Log Source
              </h2>
              {loadingDecoders ? (
                <div className="flex items-center justify-center py-8 text-zinc-500 text-sm">
                  <Loader2 className="h-4 w-4 animate-spin mr-2" /> Loading sources…
                </div>
              ) : decoders.length === 0 ? (
                <div className="text-zinc-500 text-sm py-4">No decoders available. Seed built-in decoders first.</div>
              ) : (
                <div className="space-y-2">
                  {customDecoders.length > 0 && (
                    <div className="rounded-xl border border-zinc-700 overflow-hidden">
                      <div className="px-4 py-2 bg-zinc-800/60 text-xs font-semibold text-zinc-400 uppercase tracking-wider">Custom</div>
                      <div className="grid grid-cols-2 gap-2 p-3 sm:grid-cols-3 lg:grid-cols-4">
                        {customDecoders.map((dec) => (
                          <DecoderTile key={dec.id} dec={dec} selected={sourceType === dec.name} onSelect={setSourceType} />
                        ))}
                      </div>
                    </div>
                  )}
                  {vendorGroups.map(([vendor, items]) => (
                    <div key={vendor} className="rounded-xl border border-zinc-800 overflow-hidden">
                      <button type="button" onClick={() => toggleVendor(vendor)}
                        className="w-full flex items-center gap-2 px-4 py-2.5 bg-zinc-900 hover:bg-zinc-800/80 transition-colors text-left">
                        {expandedVendors.has(vendor)
                          ? <ChevronDown  className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
                          : <ChevronRight className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
                        }
                        <span className="text-sm font-semibold text-zinc-200">{vendor}</span>
                        <span className="text-xs text-zinc-500 ml-1">{items.length} source{items.length !== 1 ? "s" : ""}</span>
                        {items.some((d) => sourceType === d.name) && <span className="ml-auto text-xs text-teal-400 font-medium">selected</span>}
                      </button>
                      {expandedVendors.has(vendor) && (
                        <div className="grid grid-cols-2 gap-2 p-3 sm:grid-cols-3 lg:grid-cols-4 border-t border-zinc-800">
                          {items.map((dec) => (
                            <DecoderTile key={dec.id} dec={dec} selected={sourceType === dec.name} onSelect={setSourceType} />
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div>
              <h2 className="text-sm font-semibold text-zinc-300 mb-3 flex items-center gap-2">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-zinc-800 text-xs text-zinc-400">3</span>
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
                  placeholder="Any additional context about this log file…"
                  className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/20 resize-none" />
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-zinc-800 pt-6">
              <Link href="/log-analysis" className="text-sm text-zinc-500 hover:text-zinc-300">Cancel</Link>
              <button onClick={handleSubmit} disabled={!canSubmit}
                className="flex items-center gap-2 rounded-lg bg-teal-600 px-6 py-2.5 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                <Upload className="h-4 w-4" />
                Normalize &amp; Analyze
              </button>
            </div>
          </div>
        )}

      </section>
    </div>
  );
}

// ── Decoder Tile ─────────────────────────────────────────────────────────────

function DecoderTile({ dec, selected, onSelect }: {
  dec:      DecoderOption;
  selected: boolean;
  onSelect: (name: string) => void;
}) {
  return (
    <button type="button" onClick={() => onSelect(dec.name)}
      className={`flex flex-col items-start gap-1 rounded-lg border p-3 text-left transition-all ${
        selected
          ? "border-teal-500 bg-teal-900/20 ring-1 ring-teal-500/30"
          : "border-zinc-700 bg-zinc-800/50 hover:border-zinc-600 hover:bg-zinc-800"
      }`}
    >
      <span className="text-sm font-medium text-zinc-200 leading-tight">{dec.title ?? dec.name}</span>
      {dec.description && <span className="text-xs text-zinc-500 leading-snug line-clamp-2">{dec.description}</span>}
    </button>
  );
}
