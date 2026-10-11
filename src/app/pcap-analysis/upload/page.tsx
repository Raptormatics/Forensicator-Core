"use client";

import { useRef, useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, CheckCircle2, Folder, Clock,
  Network, Plus, Search, Upload, X,
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
const MAX_PCAP_BYTES = 500 * 1024 * 1024;

export default function UploadPcapPage() {
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
    setIpAddress(""); setNotes(""); setError("");
    setSelectedCase(null); setPhase("case");
    setUploadPercent(0); setResultId("");
  }

  function handleSubmit() {
    if (!validated?.file || validated.error || !selectedCase) return;
    setPhase("uploading");
    setUploadPercent(0);
    setError("");

    const form = new FormData();
    form.append("file", validated.file);
    form.append("caseId", selectedCase.id);
    if (hostname) form.append("hostname", hostname);
    if (assetName) form.append("assetName", assetName);
    if (ipAddress) form.append("ipAddress", ipAddress);
    if (notes) form.append("notes", notes);

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
    xhr.addEventListener("abort", () => setPhase("details"));

    xhr.open("POST", "/api/pcap-analysis/uploads");
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
          <p className="text-zinc-300 font-medium">Uploading {validated?.file.name}…</p>
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
          <p className="text-zinc-100 text-lg font-medium">Capture queued for analysis</p>
          <p className="text-sm text-zinc-400 mt-1 mb-1 flex items-center justify-center gap-1.5">
            <Clock className="h-3.5 w-3.5" /> {validated?.file.name} will be parsed in the background.
          </p>
          <p className="text-xs text-zinc-600 mb-6">Larger captures can take a few minutes to process.</p>
          <div className="flex gap-3 justify-center">
            <button onClick={reset} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800">
              Upload another
            </button>
            <button onClick={() => router.push(`/pcap-analysis/${resultId}`)} className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500">
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
            <Link href="/pcap-analysis" className="flex items-center gap-1.5 hover:text-zinc-200">
              <ArrowLeft className="h-3.5 w-3.5" /> PCAP Analysis
            </Link>
            <span>/</span>
            <span className="text-zinc-200">Upload PCAP</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-teal-200 mb-2">
            <Network className="h-4 w-4" />
            Forensicator Enterprise
          </div>
          <h1 className="text-3xl font-semibold text-zinc-50">Upload Packet Capture</h1>
          <p className="mt-2 text-sm text-zinc-400 max-w-xl">
            Upload a .pcap or .pcapng file. Forensicator will extract conversations, DNS activity, and IOCs, and run detection rules in the background.
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
              <p className="text-xs text-zinc-500">Every PCAP upload must belong to a case.</p>
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
          <div className="space-y-4">
            <CaseBanner selectedCase={selectedCase} onChangeCase={() => { setPhase("case"); setValidated(null); }} />
            <UploadDropzone
              onFile={handleFileSelected}
              extensions={[".pcap", ".pcapng"]}
              accept={{ "application/vnd.tcpdump.pcap": [".pcap"], "application/octet-stream": [".pcap", ".pcapng"] }}
              maxSizeBytes={MAX_PCAP_BYTES}
              fileKindLabel="packet capture"
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
                      placeholder="Any additional context about this capture…"
                      className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/20 resize-none" />
                  </div>
                </div>
                <div className="flex items-center justify-between border-t border-zinc-800 pt-6">
                  <Link href="/pcap-analysis" className="text-sm text-zinc-500 hover:text-zinc-300">Cancel</Link>
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
