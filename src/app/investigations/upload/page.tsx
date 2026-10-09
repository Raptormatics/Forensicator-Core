"use client";

import { useRef, useState, useEffect } from "react";
import Link from "next/link";
import { BookOpen, ChevronRight, Upload, Folder, Plus, Search } from "lucide-react";
import { UploadDropzone, SelectedFileCard, type ValidatedFile } from "@/components/uploads/UploadDropzone";
import { UploadProgress, type UploadStage } from "@/components/uploads/UploadProgress";
import { UploadSummary, UploadErrorCard, type UploadResult } from "@/components/uploads/UploadSummary";
import { formatCaseNumber } from "@/lib/cases/case-number";

type Phase = "case" | "select" | "details" | "uploading" | "success" | "failed";

type CaseOption = {
  id: string;
  caseSeq: number;
  title: string;
  status: string;
  severity: string;
};

const CASE_SEVERITIES = ["important", "notable", "interesting", "informational"];

const PROCESSING_STAGES: UploadStage[] = ["extracting", "parsing", "findings", "timeline"];

export default function UploadInvestigationPage() {
  // ── Case state ───────────────────────────────────────────────────────────
  const [cases, setCases]               = useState<CaseOption[]>([]);
  const [selectedCase, setSelectedCase] = useState<CaseOption | null>(null);
  const [caseSearch, setCaseSearch]     = useState("");
  const [showCreateCase, setShowCreateCase] = useState(false);
  const [newCaseTitle, setNewCaseTitle]       = useState("");
  const [newCaseSeverity, setNewCaseSeverity] = useState("interesting");
  const [creatingCase, setCreatingCase] = useState(false);
  const [caseError, setCaseError]       = useState("");

  // ── File + form state ─────────────────────────────────────────────────────
  const [validated, setValidated] = useState<ValidatedFile | null>(null);
  const [title, setTitle]         = useState("");
  const [notes, setNotes]         = useState("");
  const [tags, setTags]           = useState("");

  // ── Upload state ─────────────────────────────────────────────────────────
  const [phase, setPhase]               = useState<Phase>("case");
  const [uploadPercent, setUploadPercent] = useState(0);
  const [stage, setStage]               = useState<UploadStage>("uploading");
  const [result, setResult]             = useState<UploadResult | null>(null);
  const [errorMsg, setErrorMsg]         = useState("");
  const [errorIssues, setErrorIssues]   = useState<Record<string, unknown> | string | null>(null);

  const xhrRef = useRef<XMLHttpRequest | null>(null);

  // ── Load cases ───────────────────────────────────────────────────────────
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
    setTitle(""); setNotes(""); setTags("");
  }

  function reset() {
    setValidated(null);
    setSelectedCase(null);
    setPhase("case");
    setTitle(""); setNotes(""); setTags("");
    setUploadPercent(0);
    setStage("uploading");
    setResult(null);
    setErrorMsg("");
    setErrorIssues(null);
  }

  function simulateProcessingStages() {
    let idx = 0;
    const interval = setInterval(() => {
      if (idx < PROCESSING_STAGES.length) { setStage(PROCESSING_STAGES[idx]); idx++; }
      else clearInterval(interval);
    }, 900);
    return interval;
  }

  async function startUpload() {
    if (!validated?.file || validated.error || !selectedCase) return;
    setPhase("uploading");
    setUploadPercent(0);
    setStage("uploading");

    const formData = new FormData();
    formData.append("file", validated.file);
    formData.append("caseId", selectedCase.id);
    if (title.trim()) formData.append("title", title.trim());
    if (notes.trim()) formData.append("description", notes.trim());
    const tagList = tags.split(",").map(t => t.trim()).filter(Boolean);
    if (tagList.length) formData.append("metadata", JSON.stringify({ tags: tagList }));

    const xhr = new XMLHttpRequest();
    xhrRef.current = xhr;
    const processingInterval = { current: null as ReturnType<typeof setInterval> | null };

    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 100);
        setUploadPercent(pct);
        if (pct === 100) {
          setStage("extracting");
          processingInterval.current = simulateProcessingStages();
        }
      }
    });
    xhr.addEventListener("load", () => {
      if (processingInterval.current) clearInterval(processingInterval.current);
      try {
        const data = JSON.parse(xhr.responseText);
        if (xhr.status === 201 && data.investigation) {
          setStage("completed");
          setResult(data as UploadResult);
          setPhase("success");
        } else {
          setErrorMsg(data.message ?? "Upload failed. Please try again.");
          setErrorIssues(data.issues ?? null);
          setPhase("failed");
        }
      } catch {
        setErrorMsg("Unexpected server response. Please try again.");
        setPhase("failed");
      }
    });
    xhr.addEventListener("error", () => {
      if (processingInterval.current) clearInterval(processingInterval.current);
      setErrorMsg("Network error. Check your connection and try again.");
      setPhase("failed");
    });
    xhr.addEventListener("abort", () => {
      if (processingInterval.current) clearInterval(processingInterval.current);
      setPhase("select");
    });

    xhr.open("POST", "/api/investigations/upload");
    xhr.send(formData);
  }

  function handleCancel() { xhrRef.current?.abort(); }

  // ── Derived ───────────────────────────────────────────────────────────────
  const filteredCases = cases.filter(c => {
    if (!caseSearch.trim()) return true;
    const q = caseSearch.toLowerCase();
    return c.title.toLowerCase().includes(q) || formatCaseNumber(c.caseSeq).toLowerCase().includes(q);
  });

  const steps = [
    { key: "case",    label: "Select Case" },
    { key: "select",  label: "Select File" },
    { key: "details", label: "Details" },
  ];
  const activeStepIdx = phase === "case" ? 0 : phase === "select" ? 1 : 2;

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="mx-auto max-w-2xl space-y-6">
      {/* Breadcrumb */}
      <nav className="flex items-center gap-1.5 text-sm text-zinc-500">
        <Link href="/investigations" className="flex items-center gap-1 hover:text-zinc-300">
          <BookOpen className="h-3.5 w-3.5" />
          Investigations
        </Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="text-zinc-300">Upload</span>
      </nav>

      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
          <Upload className="h-5 w-5 text-teal-400" />
          Upload Investigation
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          Upload a Forensicator collector ZIP archive to create a new investigation.
        </p>
      </div>

      {/* Step indicator */}
      {["case", "select", "details"].includes(phase) && (
        <div className="flex items-center gap-2">
          {steps.map((s, i) => (
            <div key={s.key} className="flex items-center gap-2">
              <div className={`flex items-center gap-1.5 text-xs font-medium ${i === activeStepIdx ? "text-teal-400" : i < activeStepIdx ? "text-zinc-400" : "text-zinc-600"}`}>
                <span className={`flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold border ${i === activeStepIdx ? "border-teal-400 bg-teal-400/10 text-teal-400" : i < activeStepIdx ? "border-zinc-500 bg-zinc-700 text-zinc-300" : "border-zinc-700 text-zinc-600"}`}>{i + 1}</span>
                {s.label}
              </div>
              {i < steps.length - 1 && <ChevronRight className="h-3 w-3 text-zinc-700" />}
            </div>
          ))}
        </div>
      )}

      {/* Card */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6 shadow-sm">

        {/* ── Phase: case ── */}
        {phase === "case" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-zinc-200 flex items-center gap-2 mb-1">
                <Folder className="h-4 w-4 text-teal-400" />
                Select Case
              </h2>
              <p className="text-xs text-zinc-500">Every investigation upload must belong to a case.</p>
            </div>

            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500 pointer-events-none" />
              <input
                type="text"
                value={caseSearch}
                onChange={e => setCaseSearch(e.target.value)}
                placeholder="Filter by case title or number…"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 pl-8 pr-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/20"
              />
            </div>

            {/* Cases list */}
            <div className="space-y-2 max-h-64 overflow-y-auto pr-0.5">
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
                    <button
                      onClick={() => selectCase(c)}
                      className="ml-4 shrink-0 rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-500 transition-colors"
                    >
                      Select
                    </button>
                  </div>
                ))
              )}
            </div>

            {/* Divider + create new */}
            <div className="border-t border-zinc-800 pt-4">
              <button
                onClick={() => setShowCreateCase(v => !v)}
                className="flex items-center gap-1.5 text-sm text-teal-400 hover:text-teal-300"
              >
                <Plus className="h-4 w-4" />
                {showCreateCase ? "Cancel" : "Create New Case"}
              </button>

              {showCreateCase && (
                <div className="mt-3 space-y-3 rounded-lg border border-zinc-700 bg-zinc-900 p-4">
                  {caseError && (
                    <p className="text-xs text-red-400 rounded bg-red-900/20 px-2 py-1.5">{caseError}</p>
                  )}
                  <div>
                    <label className="mb-1 block text-xs font-medium text-zinc-400">
                      Title <span className="text-red-400">*</span>
                    </label>
                    <input
                      value={newCaseTitle}
                      onChange={e => setNewCaseTitle(e.target.value)}
                      placeholder="Case title…"
                      className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs font-medium text-zinc-400">Severity</label>
                    <select
                      value={newCaseSeverity}
                      onChange={e => setNewCaseSeverity(e.target.value)}
                      className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 outline-none focus:border-teal-500"
                    >
                      {CASE_SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  <button
                    onClick={createAndSelectCase}
                    disabled={creatingCase || !newCaseTitle.trim()}
                    className="w-full rounded-md bg-teal-600 py-2 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {creatingCase ? "Creating…" : "Create & Select"}
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Phase: select ── */}
        {phase === "select" && (
          <div className="space-y-4">
            {/* Selected case banner */}
            <CaseBanner selectedCase={selectedCase} onChangeCase={() => { setPhase("case"); setValidated(null); }} />
            <UploadDropzone onFile={handleFileSelected} />
          </div>
        )}

        {/* ── Phase: details ── */}
        {phase === "details" && validated && (
          <div className="space-y-5">
            <CaseBanner selectedCase={selectedCase} />
            <SelectedFileCard file={validated.file} error={validated.error} onClear={handleClear} />

            {!validated.error && (
              <>
                <div className="space-y-3">
                  <div>
                    <label className="mb-1.5 block text-xs font-medium text-zinc-400">
                      Investigation Name <span className="text-zinc-600">(optional)</span>
                    </label>
                    <input
                      type="text"
                      value={title}
                      onChange={e => setTitle(e.target.value)}
                      placeholder="e.g. DESKTOP-ABC123 - 2026-05-29"
                      className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/20"
                    />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-xs font-medium text-zinc-400">
                      Tags <span className="text-zinc-600">(optional, comma-separated)</span>
                    </label>
                    <input
                      type="text"
                      value={tags}
                      onChange={e => setTags(e.target.value)}
                      placeholder="Incident Response, Malware, Triage"
                      className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/20"
                    />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-xs font-medium text-zinc-400">
                      Notes <span className="text-zinc-600">(optional)</span>
                    </label>
                    <textarea
                      value={notes}
                      onChange={e => setNotes(e.target.value)}
                      placeholder="Context, incident details, analyst notes…"
                      rows={3}
                      className="w-full resize-none rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/20"
                    />
                  </div>
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={startUpload}
                    className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-500 transition-colors"
                  >
                    <Upload className="h-4 w-4" />
                    Upload &amp; Process
                  </button>
                  <button
                    onClick={handleClear}
                    className="rounded-lg border border-zinc-700 px-4 py-2.5 text-sm font-medium text-zinc-400 hover:bg-zinc-800"
                  >
                    Cancel
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

        {/* ── Phase: uploading ── */}
        {phase === "uploading" && (
          <div className="space-y-6">
            <UploadProgress stage={stage} uploadPercent={uploadPercent} filename={validated?.file.name ?? ""} />
            <button onClick={handleCancel} className="w-full rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300">
              Cancel Upload
            </button>
          </div>
        )}

        {/* ── Phase: success ── */}
        {phase === "success" && result && <UploadSummary result={result} onUploadAnother={reset} />}

        {/* ── Phase: failed ── */}
        {phase === "failed" && <UploadErrorCard message={errorMsg} issues={errorIssues} onRetry={reset} />}
      </div>
    </div>
  );
}

// Small helper component — shows the selected case as a banner strip.
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

