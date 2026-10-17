"use client";

import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import Link from "next/link";
import { Settings2, Globe, FolderOutput, Database, CheckCircle2, AlertCircle, Loader2, BrainCircuit, ArrowRight, Network, MemoryStick, Bell, FileSearch } from "lucide-react";

// Core has no RBAC — the sole user always has full access.

export default function SettingsPage() {
  const { data: session } = useSession();
  // Core is single-user/single-role — the sole account always has full access.
  const isAdmin = true;

  const [appDomain, setAppDomain]   = useState("");
  const [reportsDir, setReportsDir] = useState("");
  const [pcapDir, setPcapDir]       = useState("");
  const [tsharkPath, setTsharkPath] = useState("");
  const [tsharkStatus, setTsharkStatus] = useState<{ available: boolean; path: string; version: string | null } | null>(null);
  const [ramDir, setRamDir]                             = useState("");
  const [volatilityPath, setVolatilityPath]             = useState("");
  const [volatilitySymbolsDir, setVolatilitySymbolsDir] = useState("");
  const [volatilityStatus, setVolatilityStatus] = useState<{ available: boolean; path: string; version: string | null } | null>(null);
  const [winArtifactsDir, setWinArtifactsDir]             = useState("");
  const [winArtifactsPythonPath, setWinArtifactsPythonPath] = useState("");
  const [winArtifactsBitsPythonPath, setWinArtifactsBitsPythonPath] = useState("");
  // Held in the input as MB for readability; converted to/from bytes at
  // the API boundary (winArtifactsMaxUploadBytes).
  const [winArtifactsMaxUploadMb, setWinArtifactsMaxUploadMb] = useState("");
  const [winArtifactsStatus, setWinArtifactsStatus] = useState<{
    available: boolean; path: string; version: string | null;
    bits: { available: boolean; path: string; version: string | null };
  } | null>(null);
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
        setPcapDir(d.pcapDir ?? "");
        setTsharkPath(d.tsharkPath ?? "");
        setRamDir(d.ramDir ?? "");
        setVolatilityPath(d.volatilityPath ?? "");
        setVolatilitySymbolsDir(d.volatilitySymbolsDir ?? "");
        setWinArtifactsDir(d.winArtifactsDir ?? "");
        setWinArtifactsPythonPath(d.winArtifactsPythonPath ?? "");
        setWinArtifactsBitsPythonPath(d.winArtifactsBitsPythonPath ?? "");
        setWinArtifactsMaxUploadMb(d.winArtifactsMaxUploadBytes ? String(Math.round(d.winArtifactsMaxUploadBytes / 1024 / 1024)) : "");
      })
      .finally(() => setLoading(false));

    fetch("/api/settings/pcap/tshark-status")
      .then(r => r.json())
      .then(setTsharkStatus)
      .catch(() => setTsharkStatus(null));

    fetch("/api/settings/ram/volatility-status")
      .then(r => r.json())
      .then(setVolatilityStatus)
      .catch(() => setVolatilityStatus(null));

    fetch("/api/settings/winartifacts/python-status")
      .then(r => r.json())
      .then(setWinArtifactsStatus)
      .catch(() => setWinArtifactsStatus(null));
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
          pcapDir: pcapDir.trim(),
          tsharkPath: tsharkPath.trim(),
          ramDir: ramDir.trim(),
          volatilityPath: volatilityPath.trim(),
          volatilitySymbolsDir: volatilitySymbolsDir.trim(),
          winArtifactsDir: winArtifactsDir.trim(),
          winArtifactsPythonPath: winArtifactsPythonPath.trim(),
          winArtifactsBitsPythonPath: winArtifactsBitsPythonPath.trim(),
          winArtifactsMaxUploadBytes: winArtifactsMaxUploadMb.trim() ? Math.round(Number(winArtifactsMaxUploadMb.trim()) * 1024 * 1024) : 0,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Failed to save settings.");
        return;
      }
      setAppDomain(data.appDomain ?? "");
      setReportsDir(data.reportsDir ?? "");
      setPcapDir(data.pcapDir ?? "");
      setTsharkPath(data.tsharkPath ?? "");
      setRamDir(data.ramDir ?? "");
      setVolatilityPath(data.volatilityPath ?? "");
      setVolatilitySymbolsDir(data.volatilitySymbolsDir ?? "");
      setWinArtifactsDir(data.winArtifactsDir ?? "");
      setWinArtifactsPythonPath(data.winArtifactsPythonPath ?? "");
      setWinArtifactsBitsPythonPath(data.winArtifactsBitsPythonPath ?? "");
      setWinArtifactsMaxUploadMb(data.winArtifactsMaxUploadBytes ? String(Math.round(data.winArtifactsMaxUploadBytes / 1024 / 1024)) : "");
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

        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-2">
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-teal-400" />
            <h2 className="text-sm font-semibold text-zinc-200">PCAP Storage Directory</h2>
          </div>
          <p className="text-xs text-zinc-500">
            Where uploaded packet captures are stored on disk for analysis. Leave blank to use the{" "}
            <code className="text-zinc-400">PCAP_DIR</code> environment variable, or{" "}
            <code className="text-zinc-400">./pcap-storage</code> if that&apos;s not set either.
          </p>
          <input
            type="text"
            disabled={!isAdmin}
            value={pcapDir}
            onChange={e => setPcapDir(e.target.value)}
            placeholder="/var/lib/forensicator/pcap"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          />
          <div className="flex items-center gap-2 pt-1 text-xs">
            {tsharkStatus === null ? (
              <span className="flex items-center gap-1.5 text-zinc-500"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Checking tshark…</span>
            ) : tsharkStatus.available ? (
              <span className="flex items-center gap-1.5 text-teal-400">
                <CheckCircle2 className="h-3.5 w-3.5" /> tshark available{tsharkStatus.version ? ` (${tsharkStatus.version})` : ""}
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-red-400">
                <AlertCircle className="h-3.5 w-3.5" /> tshark not found at &quot;{tsharkStatus.path}&quot; — install it (<code className="text-zinc-400">apt install tshark</code>) or set the path below.
              </span>
            )}
          </div>
          <input
            type="text"
            disabled={!isAdmin}
            value={tsharkPath}
            onChange={e => setTsharkPath(e.target.value)}
            placeholder="tshark"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          />
          <p className="text-xs text-zinc-600">
            Path to the <code className="text-zinc-500">tshark</code> binary. Leave blank to use the{" "}
            <code className="text-zinc-500">TSHARK_PATH</code> environment variable, or resolve{" "}
            <code className="text-zinc-500">tshark</code> from <code className="text-zinc-500">PATH</code> if that&apos;s not set either.
          </p>
        </div>

        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-2">
          <div className="flex items-center gap-2">
            <MemoryStick className="h-4 w-4 text-teal-400" />
            <h2 className="text-sm font-semibold text-zinc-200">RAM Storage Directory</h2>
          </div>
          <p className="text-xs text-zinc-500">
            Where uploaded memory images are stored on disk for analysis. Leave blank to use the{" "}
            <code className="text-zinc-400">RAM_DIR</code> environment variable, or{" "}
            <code className="text-zinc-400">./ram-storage</code> if that&apos;s not set either.
          </p>
          <input
            type="text"
            disabled={!isAdmin}
            value={ramDir}
            onChange={e => setRamDir(e.target.value)}
            placeholder="/var/lib/forensicator/ram"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          />
          <div className="flex items-center gap-2 pt-1 text-xs">
            {volatilityStatus === null ? (
              <span className="flex items-center gap-1.5 text-zinc-500"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Checking Volatility3…</span>
            ) : volatilityStatus.available ? (
              <span className="flex items-center gap-1.5 text-teal-400">
                <CheckCircle2 className="h-3.5 w-3.5" /> Volatility3 available{volatilityStatus.version ? ` (v${volatilityStatus.version})` : ""}
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-red-400">
                <AlertCircle className="h-3.5 w-3.5" /> Volatility3 not found at &quot;{volatilityStatus.path}&quot; — install it (see deploy/provision.sh) or set the path below.
              </span>
            )}
          </div>
          <input
            type="text"
            disabled={!isAdmin}
            value={volatilityPath}
            onChange={e => setVolatilityPath(e.target.value)}
            placeholder="/opt/forensicator/.venvs/volatility3/bin/vol"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          />
          <p className="text-xs text-zinc-600">
            Path to the <code className="text-zinc-500">vol</code> binary. Leave blank to use the{" "}
            <code className="text-zinc-500">VOLATILITY_PATH</code> environment variable, or the bundled venv at{" "}
            <code className="text-zinc-500">.venvs/volatility3/bin/vol</code> if that&apos;s not set either.
          </p>
          <input
            type="text"
            disabled={!isAdmin}
            value={volatilitySymbolsDir}
            onChange={e => setVolatilitySymbolsDir(e.target.value)}
            placeholder="/var/lib/forensicator/volatility-symbols"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          />
          <p className="text-xs text-zinc-600">
            Optional local symbol-table cache directory. Leave blank to let Volatility3 use its own bundled cache and,
            for unseen Windows builds, fetch from the public symbol server over the network. Pre-staging this speeds up
            repeat analysis and helps air-gapped deployments.
          </p>
        </div>

        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-2">
          <div className="flex items-center gap-2">
            <FileSearch className="h-4 w-4 text-teal-400" />
            <h2 className="text-sm font-semibold text-zinc-200">Windows Artifact Storage Directory</h2>
          </div>
          <p className="text-xs text-zinc-500">
            Where uploaded registry hives, Prefetch, and LNK/Jump List files are stored on disk for analysis. Leave
            blank to use the <code className="text-zinc-400">WIN_ARTIFACTS_DIR</code> environment variable, or{" "}
            <code className="text-zinc-400">./winartifacts-storage</code> if that&apos;s not set either.
          </p>
          <input
            type="text"
            disabled={!isAdmin}
            value={winArtifactsDir}
            onChange={e => setWinArtifactsDir(e.target.value)}
            placeholder="/var/lib/forensicator/winartifacts"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          />
          <div className="flex items-center gap-2 pt-1 text-xs">
            {winArtifactsStatus === null ? (
              <span className="flex items-center gap-1.5 text-zinc-500"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Checking regipy…</span>
            ) : winArtifactsStatus.available ? (
              <span className="flex items-center gap-1.5 text-teal-400">
                <CheckCircle2 className="h-3.5 w-3.5" /> regipy available{winArtifactsStatus.version ? ` (v${winArtifactsStatus.version})` : ""}
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-red-400">
                <AlertCircle className="h-3.5 w-3.5" /> regipy not found at &quot;{winArtifactsStatus.path}&quot; — install it (see deploy/provision.sh) or set the path below.
              </span>
            )}
          </div>
          <input
            type="text"
            disabled={!isAdmin}
            value={winArtifactsPythonPath}
            onChange={e => setWinArtifactsPythonPath(e.target.value)}
            placeholder="/opt/forensicator/.venvs/winartifacts/bin/python3"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          />
          <p className="text-xs text-zinc-600">
            Path to the Windows Artifact Analysis venv&apos;s <code className="text-zinc-500">python3</code>. Leave blank to use the{" "}
            <code className="text-zinc-500">WIN_ARTIFACTS_PYTHON_PATH</code> environment variable, or the bundled venv at{" "}
            <code className="text-zinc-500">.venvs/winartifacts/bin/python3</code> if that&apos;s not set either.
          </p>

          <div className="flex items-center gap-2 pt-1 text-xs">
            {winArtifactsStatus === null ? (
              <span className="flex items-center gap-1.5 text-zinc-500"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Checking bits_parser…</span>
            ) : winArtifactsStatus.bits.available ? (
              <span className="flex items-center gap-1.5 text-teal-400">
                <CheckCircle2 className="h-3.5 w-3.5" /> bits_parser available
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-red-400">
                <AlertCircle className="h-3.5 w-3.5" /> bits_parser not found at &quot;{winArtifactsStatus.bits.path}&quot; — install it (see deploy/provision.sh) or set the path below.
              </span>
            )}
          </div>
          <input
            type="text"
            disabled={!isAdmin}
            value={winArtifactsBitsPythonPath}
            onChange={e => setWinArtifactsBitsPythonPath(e.target.value)}
            placeholder="/opt/forensicator/.venvs/winartifacts-bits/bin/python3"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          />
          <p className="text-xs text-zinc-600">
            Path to the BITS job database venv&apos;s <code className="text-zinc-500">python3</code> — kept separate from the venv above
            because bits_parser and regipy need incompatible versions of a shared dependency and can never install together. Leave blank
            to use the <code className="text-zinc-500">WIN_ARTIFACTS_BITS_PYTHON_PATH</code> environment variable, or the bundled venv at{" "}
            <code className="text-zinc-500">.venvs/winartifacts-bits/bin/python3</code> if that&apos;s not set either.
          </p>

          <label className="block pt-2 text-xs text-zinc-400">Max upload size (MB)</label>
          <input
            type="number"
            min={1}
            disabled={!isAdmin}
            value={winArtifactsMaxUploadMb}
            onChange={e => setWinArtifactsMaxUploadMb(e.target.value)}
            placeholder="5120"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          />
          <p className="text-xs text-zinc-600">
            Combined size cap for one Windows Artifact Analysis upload — registry hives with their .LOG1/.LOG2
            files, $MFT, Prefetch, and WER crash dumps all add up, and a busy workstation&apos;s $MFT alone can run
            1-2+ GB. Leave blank to use the <code className="text-zinc-400">WIN_ARTIFACTS_MAX_UPLOAD_BYTES</code>{" "}
            environment variable, or 5120 MB (5GB) if that&apos;s not set either.
          </p>
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

      <Link
        href="/settings/notifications"
        className="flex items-center justify-between rounded-xl border border-zinc-800 bg-zinc-900 p-4 hover:border-teal-700/50 hover:bg-zinc-800/60"
      >
        <div className="flex items-center gap-2">
          <Bell className="h-4 w-4 text-teal-400" />
          <div>
            <h2 className="text-sm font-semibold text-zinc-200">Critical Finding Alerts</h2>
            <p className="text-xs text-zinc-500">Configure SMTP and get emailed when a critical-severity finding is detected.</p>
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
