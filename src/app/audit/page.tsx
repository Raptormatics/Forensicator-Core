"use client";
import { useEffect, useState, useCallback } from "react";
import { RefreshCw, ScrollText } from "lucide-react";

interface AuditEntry {
  id: string; action: string; actorEmail: string; resourceType?: string;
  resourceId?: string; severity: string; ipAddress?: string; createdAt: string;
  metadata?: Record<string, unknown>;
}

const SEV_COLORS: Record<string, string> = {
  info:     "bg-blue-900/30 text-blue-400",
  warning:  "bg-yellow-900/30 text-yellow-400",
  error:    "bg-red-900/30 text-red-400",
  critical: "bg-red-900/60 text-red-300",
};

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({ page: String(page), limit: "50" });
    if (q) params.set("q", q);
    if (severity) params.set("severity", severity);
    const r = await fetch(`/api/audit?${params}`);
    const d = await r.json();
    setLogs(d.logs ?? []);
    setTotal(d.total ?? 0);
    setPages(d.pages ?? 1);
    setLoading(false);
  }, [page, q, severity]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="mx-auto max-w-6xl px-6 py-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">Audit Log</h1>
          <p className="text-sm text-zinc-500">Immutable security event trail · {total.toLocaleString()} entries</p>
        </div>
        <button onClick={load} className="text-zinc-600 hover:text-zinc-300"><RefreshCw className="h-4 w-4" /></button>
      </div>

      <div className="flex gap-3 flex-wrap">
        <input value={q} onChange={e => { setQ(e.target.value); setPage(1); }} placeholder="Search actions, actors…" className="rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500 w-64" />
        <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }} className="rounded border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 outline-none">
          <option value="">All severities</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="error">Error</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      {loading ? <p className="text-sm text-zinc-500">Loading…</p> : logs.length === 0 ? (
        <div className="rounded-lg border border-dashed border-zinc-800 p-12 text-center text-zinc-600">
          <ScrollText className="mx-auto mb-2 h-8 w-8" /> No audit entries
        </div>
      ) : (
        <>
          <div className="overflow-hidden rounded-lg border border-zinc-800 text-sm">
            <table className="w-full">
              <thead className="bg-zinc-900 text-zinc-500 text-xs uppercase">
                <tr>
                  <th className="px-4 py-2 text-left">Time</th>
                  <th className="px-4 py-2 text-left">Actor</th>
                  <th className="px-4 py-2 text-left">Action</th>
                  <th className="px-4 py-2 text-left">Resource</th>
                  <th className="px-4 py-2 text-left">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {logs.map(l => (
                  <tr key={l.id} className="bg-zinc-950 hover:bg-zinc-900/50">
                    <td className="px-4 py-2 font-mono text-xs text-zinc-600 whitespace-nowrap">{new Date(l.createdAt).toISOString().replace("T", " ").slice(0, 19)}</td>
                    <td className="px-4 py-2 text-zinc-400 text-xs truncate max-w-[160px]">{l.actorEmail}</td>
                    <td className="px-4 py-2 font-mono text-xs text-zinc-300">{l.action}</td>
                    <td className="px-4 py-2 text-xs text-zinc-500">{l.resourceType}{l.resourceId ? ` / ${l.resourceId.slice(0,8)}` : ""}</td>
                    <td className="px-4 py-2">
                      <span className={`rounded px-1.5 py-0.5 text-xs ${SEV_COLORS[l.severity] ?? "bg-zinc-800 text-zinc-500"}`}>{l.severity}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between text-xs text-zinc-600">
            <span>Page {page} of {pages}</span>
            <div className="flex gap-2">
              <button disabled={page <= 1} onClick={() => setPage(p => p - 1)} className="rounded border border-zinc-700 px-2 py-1 hover:text-zinc-300 disabled:opacity-40">Prev</button>
              <button disabled={page >= pages} onClick={() => setPage(p => p + 1)} className="rounded border border-zinc-700 px-2 py-1 hover:text-zinc-300 disabled:opacity-40">Next</button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
