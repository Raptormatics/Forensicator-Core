"use client";

import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import Link from "next/link";
import { Settings2, Globe, FolderOutput, Database, CheckCircle2, AlertCircle, Loader2, BrainCircuit, ArrowRight } from "lucide-react";

// Mirrors isInstanceAdmin() (src/lib/auth/session.ts), which the API
// route actually enforces — this only gates the UI, not security. System
// settings affect the whole shared platform in SaaS mode (every org), so
// they stay platform_admin-only there; appliance mode never seeds a
// platform_admin, so org_admin manages their own single instance's copy.
const IS_APPLIANCE = process.env.NEXT_PUBLIC_DEPLOYMENT_MODE === "appliance";
const ADMIN_ROLES = IS_APPLIANCE ? ["platform_admin", "org_admin"] : ["platform_admin"];

export default function SettingsPage() {
  const { data: session } = useSession();
  const isAdmin = ADMIN_ROLES.includes(session?.user?.role ?? "");

  const [appDomain, setAppDomain]   = useState("");
  const [reportsDir, setReportsDir] = useState("");
  const [loading, setLoading]       = useState(true);
  const [saving, setSaving]         = useState(false);
  const [error, setError]           = useState("");
  const [saved, setSaved]           = useState(false);

  useEffect(() => {
    fetch("/api/settings/system")
      .then(r => r.json())
      .then(d => {
        setAppDomain(d.appDomain ?? "");
        setReportsDir(d.reportsDir ?? "");
      })
      .finally(() => setLoading(false));
  }, []);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSaved(false);
    setSaving(true);
    try {
      const res = await fetch("/api/settings/system", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          appDomain: appDomain.trim(),
          reportsDir: reportsDir.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Failed to save settings.");
        return;
      }
      setAppDomain(data.appDomain ?? "");
      setReportsDir(data.reportsDir ?? "");
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch {
      setError("Failed to save settings.");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <div className="px-6 py-8 text-sm text-zinc-500">Loading…</div>;

  return (
    <div className="mx-auto max-w-2xl px-6 py-8 space-y-8">
      <div className="flex items-center gap-3">
        <Settings2 className="h-5 w-5 text-teal-400" />
        <div>
          <h1 className="text-xl font-bold text-zinc-100">General</h1>
          <p className="text-sm text-zinc-500">Instance-wide configuration for this Forensicator deployment.</p>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-900 bg-red-950/50 px-4 py-3">
          <AlertCircle className="h-4 w-4 shrink-0 text-red-400" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-4">
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-2">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-teal-400" />
            <h2 className="text-sm font-semibold text-zinc-200">App Domain</h2>
          </div>
          <p className="text-xs text-zinc-500">
            This instance&apos;s own public URL — e.g. <code className="text-zinc-400">https://forensicator.tesco.com</code> or{" "}
            <code className="text-zinc-400">http://tescoserver.local</code>, once you&apos;ve pointed DNS at this
            instance&apos;s IP. Used to show a real, stable base URL in the API docs instead of guessing from whatever
            address you happen to be browsing from right now. Leave blank to fall back to that.
          </p>
          <input
            type="text"
            disabled={!isAdmin}
            value={appDomain}
            onChange={e => setAppDomain(e.target.value)}
            placeholder="https://forensicator.example.com"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          />
        </div>

        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-2">
          <div className="flex items-center gap-2">
            <FolderOutput className="h-4 w-4 text-teal-400" />
            <h2 className="text-sm font-semibold text-zinc-200">Reports Output Directory</h2>
          </div>
          <p className="text-xs text-zinc-500">
            Where generated PDF/CSV/JSON/ZIP reports are written. Leave blank to use the{" "}
            <code className="text-zinc-400">REPORTS_DIR</code> environment variable, or{" "}
            <code className="text-zinc-400">./reports-output</code> if that&apos;s not set either.
          </p>
          <input
            type="text"
            disabled={!isAdmin}
            value={reportsDir}
            onChange={e => setReportsDir(e.target.value)}
            placeholder="/var/lib/forensicator/reports"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          />
        </div>

        {isAdmin && (
          <button
            type="submit"
            disabled={saving}
            className="flex items-center gap-2 rounded-lg bg-teal-700 px-4 py-2 text-sm font-semibold text-white hover:bg-teal-600 disabled:opacity-60"
          >
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            {saved && <CheckCircle2 className="h-4 w-4" />}
            {saving ? "Saving…" : saved ? "Saved" : "Save changes"}
          </button>
        )}
      </form>

      <Link
        href="/settings/ai"
        className="flex items-center justify-between rounded-xl border border-zinc-800 bg-zinc-900 p-4 hover:border-teal-700/50 hover:bg-zinc-800/60"
      >
        <div className="flex items-center gap-2">
          <BrainCircuit className="h-4 w-4 text-teal-400" />
          <div>
            <h2 className="text-sm font-semibold text-zinc-200">AI Analysis</h2>
            <p className="text-xs text-zinc-500">Moved — configure the Ollama/OpenAI/Anthropic provider, install a local model, and manage the service here.</p>
          </div>
        </div>
        <ArrowRight className="h-4 w-4 shrink-0 text-zinc-600" />
      </Link>

      {/* Redis — infrastructure wiring, not a live setting. Read once at
          process boot to build the connection pool; changing it here
          couldn't safely take effect without a restart, so it stays
          env-var/restart-only rather than pretending to be editable. */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-1">
        <div className="flex items-center gap-2">
          <Database className="h-4 w-4 text-zinc-500" />
          <h2 className="text-sm font-semibold text-zinc-200">Redis Connection</h2>
        </div>
        <p className="text-xs text-zinc-500">
          Read once at startup to connect the background job queue — not editable here. To change it, set{" "}
          <code className="text-zinc-400">REDIS_HOST</code>, <code className="text-zinc-400">REDIS_PORT</code>, and{" "}
          <code className="text-zinc-400">REDIS_PASSWORD</code> in the environment and restart the service.
        </p>
      </div>
    </div>
  );
}
