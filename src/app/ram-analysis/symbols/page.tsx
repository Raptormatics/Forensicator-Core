"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, FileJson, Loader2, MemoryStick,
  Plus, RefreshCw, Trash2, Upload,
} from "lucide-react";

type SymbolTable = {
  id: string;
  osType: string;
  filename: string;
  description: string | null;
  fileSize: number;
  createdAt: string;
  uploadedBy: { email: string; name: string | null } | null;
  organization: { id: string; name: string } | null;
};

const OS_LABEL: Record<string, string> = { linux: "Linux", mac: "macOS" };

function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export default function RamSymbolTablesPage() {
  const [tables, setTables]   = useState<SymbolTable[]>([]);
  const [loading, setLoading] = useState(true);
  const [showUpload, setShowUpload] = useState(false);

  const [file, setFile]             = useState<File | null>(null);
  const [osType, setOsType]         = useState<"linux" | "mac">("linux");
  const [description, setDescription] = useState("");
  const [uploading, setUploading]   = useState(false);
  const [error, setError]           = useState("");

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/ram-analysis/symbols");
      const data = await res.json();
      setTables(data.symbolTables ?? []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleUpload() {
    if (!file) { setError("Choose a file first."); return; }
    setUploading(true);
    setError("");
    try {
      const form = new FormData();
      form.append("osType", osType);
      if (description.trim()) form.append("description", description.trim());
      form.append("file", file);

      const res = await fetch("/api/ram-analysis/symbols", { method: "POST", body: form });
      const data = await res.json();
      if (!res.ok) {
        setError(data.message ?? data.error ?? "Upload failed.");
        return;
      }
      setFile(null);
      setDescription("");
      setShowUpload(false);
      load();
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setUploading(false);
    }
  }

  async function deleteTable(id: string) {
    if (!confirm("Delete this symbol table? Any pending Linux/macOS analyses relying on it will fail until you upload a replacement.")) return;
    await fetch(`/api/ram-analysis/symbols/${id}`, { method: "DELETE" });
    load();
  }

  return (
    <div className="min-h-screen">
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto w-full max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
          <div className="flex items-center gap-2 text-sm text-zinc-500 mb-4">
            <Link href="/ram-analysis" className="flex items-center gap-1.5 hover:text-zinc-300">
              <ArrowLeft className="h-3.5 w-3.5" /> RAM Analysis
            </Link>
            <span>/</span>
            <span className="text-zinc-300">Symbol Tables</span>
          </div>
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="flex items-center gap-2 text-sm text-teal-200 mb-1">
                <MemoryStick className="h-4 w-4" /> RAM Analysis
              </div>
              <h1 className="text-3xl font-semibold text-zinc-50">Symbol Tables</h1>
              <p className="mt-2 text-sm text-zinc-400 max-w-xl">
                Linux and macOS memory analysis needs a Volatility3 ISF symbol table matching the exact source kernel/OS
                build — unlike Windows, there&apos;s no automatic fetch. Generate one externally with{" "}
                <code className="text-zinc-500">dwarf2json</code> from the matching debug symbols, then upload it here.
                It applies to every future upload from that same build.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button onClick={load} className="p-2.5 rounded-lg border border-zinc-700 text-zinc-500 hover:text-zinc-200">
                <RefreshCw className="h-4 w-4" />
              </button>
              <button
                onClick={() => setShowUpload((v) => !v)}
                className="flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-500"
              >
                <Plus className="h-4 w-4" /> Upload Symbol Table
              </button>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto w-full max-w-5xl px-4 py-6 sm:px-6 lg:px-8 space-y-6">
        {showUpload && (
          <div className="rounded-xl border border-zinc-700 bg-zinc-900 p-6 space-y-4">
            {error && (
              <div className="flex items-center gap-2 text-sm text-red-400 bg-red-950/20 border border-red-900/40 rounded-lg px-3 py-2">
                <AlertCircle className="h-4 w-4 shrink-0" /> {error}
              </div>
            )}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="block text-xs text-zinc-400 mb-1.5">Operating System</label>
                <select
                  value={osType}
                  onChange={(e) => setOsType(e.target.value as "linux" | "mac")}
                  className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-teal-500"
                >
                  <option value="linux">Linux</option>
                  <option value="mac">macOS</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-zinc-400 mb-1.5">Description <span className="text-zinc-600">(optional)</span></label>
                <input
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="e.g. Ubuntu 22.04, kernel 5.15.0-91-generic"
                  className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-teal-500"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1.5">ISF File</label>
              <label className="flex items-center gap-3 rounded-lg border border-dashed border-zinc-700 bg-zinc-800/50 px-4 py-4 cursor-pointer hover:border-zinc-600">
                <input
                  type="file"
                  accept=".json,.xz,.gz,.bz2"
                  className="hidden"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
                <FileJson className="h-5 w-5 text-zinc-500 shrink-0" />
                <span className="text-sm text-zinc-300 truncate">{file ? file.name : "Choose a .json / .json.xz / .json.gz / .json.bz2 file…"}</span>
              </label>
            </div>
            <div className="flex items-center justify-between border-t border-zinc-800 pt-4">
              <button onClick={() => { setShowUpload(false); setFile(null); setError(""); }} className="text-sm text-zinc-500 hover:text-zinc-300">
                Cancel
              </button>
              <button
                onClick={handleUpload}
                disabled={uploading || !file}
                className="flex items-center gap-2 rounded-lg bg-teal-600 px-5 py-2 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50"
              >
                <Upload className="h-4 w-4" />
                {uploading ? "Uploading…" : "Upload"}
              </button>
            </div>
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-16 text-zinc-500">
            <Loader2 className="h-6 w-6 animate-spin" />
          </div>
        ) : tables.length === 0 && !showUpload ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-zinc-700 py-16 text-center">
            <FileJson className="h-10 w-10 text-zinc-600 mb-3" />
            <p className="text-sm text-zinc-400 font-medium">No symbol tables uploaded yet</p>
            <p className="mt-1 text-xs text-zinc-600 max-w-sm">
              Windows RAM analysis doesn&apos;t need this — Volatility3 resolves Windows symbols automatically.
              Linux and macOS uploads will fail until a matching symbol table is available here.
            </p>
          </div>
        ) : (
          <div className="rounded-xl border border-zinc-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 bg-zinc-900">
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">File</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">OS</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Description</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-zinc-500 uppercase tracking-wider">Size</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Uploaded</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800 bg-zinc-950">
                {tables.map((t) => (
                  <tr key={t.id} className="hover:bg-zinc-900/50 transition-colors">
                    <td className="px-4 py-3 max-w-[220px] font-mono text-xs text-zinc-300 truncate">{t.filename}</td>
                    <td className="px-4 py-3 text-zinc-400">{OS_LABEL[t.osType] ?? t.osType}</td>
                    <td className="px-4 py-3 text-zinc-400 text-xs max-w-[280px] truncate">{t.description ?? "—"}</td>
                    <td className="px-4 py-3 text-right text-zinc-400 text-xs">{formatBytes(t.fileSize)}</td>
                    <td className="px-4 py-3 text-zinc-500 text-xs whitespace-nowrap">{new Date(t.createdAt).toLocaleString()}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => deleteTable(t.id)}
                        className="p-1.5 rounded text-zinc-600 hover:text-red-400 hover:bg-red-900/20 transition-colors"
                        title="Delete"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
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
