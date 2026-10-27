"use client";
/**
 * Settings → Threat Intelligence: Core's SigmaHQ rule library — which
 * release package is in use, when it was last downloaded, and an "Update
 * rules" button (instance admins). Shared by Core's page and the
 * Enterprise overlay's version of it.
 */
import { useEffect, useState } from "react";
import Link from "next/link";
import { RefreshCw, ShieldAlert } from "lucide-react";

type LibraryState = {
  package: string;
  releaseTag: string | null;
  syncedAt: string | null;
  ruleCount: number;
  supportedCount: number;
  coveredCount: number;
  activeCount: number;
  disabledCount: number;
  lastError: string | null;
  packages: { id: string; label: string; description: string }[];
};

export function SigmaRulesCard({ canManage }: { canManage: boolean }) {
  const [state, setState] = useState<LibraryState | null>(null);
  const [pkg, setPkg] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function load() {
    const r = await fetch("/api/sigma/library");
    if (r.ok) {
      const d = (await r.json()) as LibraryState;
      setState(d);
      setPkg((p) => p || d.package);
    }
  }
  useEffect(() => { load(); }, []);

  async function update() {
    setBusy(true);
    setMsg("Downloading and compiling the SigmaHQ rules — this takes a minute…");
    try {
      const r = await fetch("/api/sigma/library", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ package: pkg }),
      });
      const d = await r.json();
      if (r.ok) {
        setMsg(`Updated to SigmaHQ ${d.releaseTag}: ${d.total.toLocaleString()} rules (${d.added} new, ${d.removed} removed), ${d.covered.toLocaleString()} runnable on the logs Core receives.`);
      } else {
        setMsg(d.message ?? d.error ?? "Update failed.");
      }
    } catch {
      setMsg("Update failed.");
    } finally {
      setBusy(false);
      load();
    }
  }

  const unsupported = state ? state.ruleCount - state.supportedCount : 0;
  const noSource = state ? state.supportedCount - state.coveredCount : 0;
  const chosen = state?.packages.find((p) => p.id === pkg);

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-orange-400" />
          <span className="font-medium text-zinc-200">SigmaHQ rules</span>
          <span className={`rounded-full px-2 py-0.5 text-xs ${state && state.activeCount > 0 ? "bg-teal-900/50 text-teal-400" : "bg-zinc-800 text-zinc-500"}`}>
            {state && state.activeCount > 0 ? `${state.activeCount.toLocaleString()} active` : "Not downloaded"}
          </span>
        </div>
        <Link href="/intelligence/sigma?tab=rules" className="text-xs text-teal-400 hover:text-teal-300">Rule library →</Link>
      </div>
      <p className="text-xs text-zinc-500">
        Core runs the community Sigma rules against every Log Analysis upload — Windows event logs (including Sysmon and
        PowerShell), Linux auth, syslog and auditd, web server, firewall and DNS logs, and cloud audit logs uploaded as JSON
        lines. Matches appear as findings on the upload and under Intelligence → Sigma Detections.
      </p>

      {state && (
        <div className="text-xs text-zinc-500 space-y-0.5">
          <div>
            {state.syncedAt
              ? <>Release <span className="text-zinc-300">{state.releaseTag}</span> · updated {new Date(state.syncedAt).toLocaleString()}</>
              : "Never downloaded"}
          </div>
          {state.ruleCount > 0 && (
            <div>
              {state.ruleCount.toLocaleString()} rules · {state.coveredCount.toLocaleString()} runnable
              {noSource > 0 && <> · {noSource.toLocaleString()} for log sources Core doesn&apos;t receive</>}
              {unsupported > 0 && <> · {unsupported.toLocaleString()} not supported</>}
              {state.disabledCount > 0 && <> · {state.disabledCount.toLocaleString()} turned off</>}
            </div>
          )}
          {state.lastError && <div className="text-red-400">Last update failed: {state.lastError}</div>}
        </div>
      )}

      {canManage && state && (
        <div className="flex flex-wrap items-center gap-2 border-t border-zinc-800 pt-3">
          <select
            value={pkg}
            onChange={(e) => setPkg(e.target.value)}
            disabled={busy}
            className="rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-300 outline-none focus:border-teal-500"
          >
            {state.packages.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
          </select>
          {chosen && <span className="text-xs text-zinc-600">{chosen.description}</span>}
          <button
            onClick={update}
            disabled={busy}
            className="ml-auto flex items-center gap-1.5 rounded-md border border-zinc-800 px-2.5 py-1 text-xs text-zinc-400 hover:text-zinc-200 hover:border-zinc-600 disabled:opacity-50"
          >
            <RefreshCw className={`h-3 w-3 ${busy ? "animate-spin" : ""}`} /> {busy ? "Updating…" : state.syncedAt ? "Update rules" : "Download rules"}
          </button>
        </div>
      )}
      {msg && <p className="text-xs text-zinc-400">{msg}</p>}
    </div>
  );
}
