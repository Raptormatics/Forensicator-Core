"use client";

import { useEffect, useRef, useState } from "react";
import { FileText, ShieldCheck, Trash2, Upload, X } from "lucide-react";

// Known-good file hash allowlisting (NSRL-style) — import a hash set once
// per case; the Artifact Explorer (src/components/artifacts/artifact-explorer.tsx)
// uses it to filter known-OS/application-file noise out of triage. Import
// lives here (case-level, one action) rather than on the Artifact Explorer
// itself (investigation-level, where you're browsing, not importing).

type ImportResult = { total: number; linked: number; skipped: number; skippedSamples: string[]; truncated: boolean };

export function CaseKnownHashesSection({ caseId }: { caseId: string }) {
  const [count, setCount] = useState<number | null>(null);
  const [showUpload, setShowUpload] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState<"custom" | "nsrl">("custom");
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function loadCount() {
    const res = await fetch(`/api/known-hashes?caseId=${caseId}`);
    if (res.ok) setCount((await res.json()).count ?? 0);
  }

  useEffect(() => { loadCount(); }, [caseId]); // eslint-disable-line react-hooks/exhaustive-deps

  async function uploadHashList() {
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    setResult(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("caseId", caseId);
      formData.append("source", source);
      const res = await fetch("/api/known-hashes/import", { method: "POST", body: formData });
      const json = await res.json().catch(() => ({}));
      if (res.ok) {
        setResult(json);
        setFile(null);
        if (fileInputRef.current) fileInputRef.current.value = "";
        loadCount();
      } else {
        setUploadError(json.message ?? "Upload failed.");
      }
    } catch {
      setUploadError("Upload failed — check your connection and try again.");
    } finally {
      setUploading(false);
    }
  }

  async function clearAll() {
    if (!confirm("Remove every known-good hash from this case? Evidence that was being hidden will reappear in the Artifact Explorer.")) return;
    const res = await fetch(`/api/known-hashes?caseId=${caseId}`, { method: "DELETE" });
    if (res.ok) loadCount();
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-zinc-500" /> Known-Good Hashes
        </h2>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { setShowUpload((v) => !v); setUploadError(null); setResult(null); }}
            className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium ${
              showUpload ? "border-teal-700 bg-teal-900/30 text-teal-300" : "border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-600"
            }`}
          >
            <Upload className="h-3.5 w-3.5" /> Import
          </button>
          {count !== null && count > 0 && (
            <button onClick={clearAll} title="Remove all known-good hashes from this case" className="p-1.5 rounded-md border border-zinc-800 text-zinc-500 hover:text-red-400 hover:border-red-900">
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      <p className="text-xs text-zinc-500 mb-3">
        {count === null ? "Loading…" : count === 0
          ? "No known-good hashes imported for this case yet — import an NSRL set or a custom list to filter known-OS/application-file noise out of the Artifact Explorer."
          : `${count.toLocaleString()} known-good hash${count !== 1 ? "es" : ""} imported — hidden by default wherever evidence is browsed for this case's investigations.`}
      </p>

      {showUpload && (
        <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 mb-2">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h3 className="text-sm font-semibold text-zinc-300">Import known-good hashes</h3>
              <p className="text-xs text-zinc-500 mt-0.5">
                A plaintext or CSV file, one MD5/SHA1/SHA256 hash per line (optionally &quot;hash,note&quot;).
                Lines starting with # and blank lines are ignored.
              </p>
            </div>
            <button onClick={() => setShowUpload(false)} className="text-zinc-600 hover:text-zinc-300">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 rounded-md border border-dashed border-zinc-700 px-3 py-2 text-sm text-zinc-400 hover:border-teal-600 hover:text-teal-400 cursor-pointer">
              <FileText className="h-4 w-4" />
              {file ? file.name : "Choose .txt/.csv file…"}
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.csv,text/plain,text/csv"
                className="hidden"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </label>
            <select
              value={source}
              onChange={(e) => setSource(e.target.value as "custom" | "nsrl")}
              className="rounded-md border border-zinc-700 bg-zinc-800 px-2.5 py-2 text-xs text-zinc-300 outline-none focus:border-teal-500"
            >
              <option value="custom">Custom set</option>
              <option value="nsrl">NSRL set</option>
            </select>
            <button
              onClick={uploadHashList}
              disabled={!file || uploading}
              className="rounded-md bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50"
            >
              {uploading ? "Uploading…" : "Upload"}
            </button>
          </div>
          {uploadError && (
            <p className="mt-3 text-xs rounded px-2 py-1.5 bg-red-900/30 text-red-400">{uploadError}</p>
          )}
          {result && (
            <div className="mt-3 rounded-md border border-zinc-800 bg-zinc-950 p-3 text-xs text-zinc-400 space-y-1">
              <p>
                <span className="text-teal-400 font-medium">{result.linked}</span> linked to this case,{" "}
                <span className={result.skipped > 0 ? "text-orange-400" : "text-zinc-300"}>{result.skipped}</span> skipped (unrecognized format)
              </p>
              {result.truncated && (
                <p className="text-orange-400">File exceeded 200,000 lines — only the first 200,000 were processed.</p>
              )}
              {result.skippedSamples.length > 0 && (
                <details className="mt-1">
                  <summary className="cursor-pointer text-zinc-500 hover:text-zinc-300">Show skipped line samples</summary>
                  <ul className="mt-1 space-y-0.5 font-mono">
                    {result.skippedSamples.map((s, i) => <li key={i} className="truncate">{s}</li>)}
                  </ul>
                </details>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
