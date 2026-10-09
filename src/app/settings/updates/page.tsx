"use client";
import { useEffect, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import Link from "next/link";
import { CloudDownload, PackageCheck, RefreshCw, ShieldOff, Undo2, UploadCloud, Sparkles, ArrowRight } from "lucide-react";

type BackupManifest = {
  id: string;
  reason: string;
  fromVersion: string;
  toVersion: string;
  createdAt: string;
};
type UpdateResult = {
  success: boolean;
  toVersion: string;
  fromVersion: string;
  rolledBack: boolean;
  error: string | null;
  completedAt: string;
};
type Progress = { stage: string; message: string; updatedAt: string };
type DeltaState = {
  applied: boolean;
  version: string | null;
  requiresCoreVersion: string | null;
  appliedAt: string | null;
};
type Status = {
  installedVersion: string;
  backups: { manifest: BackupManifest; result: UpdateResult | null }[];
  progress: Progress | null;
  delta: DeltaState;
  licensed: boolean;
};
type LatestUpdateInfo = {
  version: string;
  releaseNotes: string;
  packageUrl: string;
  packageSha256: string;
  packageSize?: number;
  publishedAt?: string;
};
type LatestOverlayInfo = LatestUpdateInfo & { requiresCoreVersion: string };
type CheckResult =
  | { configured: false }
  | { configured: true; ok: true; latest: LatestUpdateInfo; updateAvailable: boolean }
  | { configured: true; ok: false; error: string };
type OverlayCheckResult =
  | { licensed: false }
  | { licensed: true; ok: true; latest: LatestOverlayInfo; updateAvailable: boolean; coreVersionSatisfied: boolean }
  | { licensed: true; ok: false; error: string };

// Appliance mode never seeds a platform_admin — only ever org_admin, who
// is the sole tenant's own admin — so org_admin manages updates there too.
// In SaaS mode, updates affect the whole shared platform across every
// org, so it stays platform_admin-only.
const IS_APPLIANCE = process.env.NEXT_PUBLIC_DEPLOYMENT_MODE === "appliance";
const ADMIN_ROLES = IS_APPLIANCE ? ["platform_admin", "org_admin"] : ["platform_admin"];
const CHANNELS = ["stable", "beta", "preview"] as const;

function formatBytes(bytes?: number): string {
  if (!bytes) return "";
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export default function UpdatesPage() {
  const { data: session } = useSession();
  const isAdmin = ADMIN_ROLES.includes(session?.user?.role ?? "");

  const [status, setStatus]     = useState<Status | null>(null);
  const [loading, setLoading]   = useState(true);
  const [busy, setBusy]         = useState(false);
  const [file, setFile]         = useState<File | null>(null);
  const [allowDowngrade, setAllowDowngrade] = useState(false);
  const [error, setError]       = useState("");
  const [restarting, setRestarting] = useState(false);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [channel, setChannelState] = useState<(typeof CHANNELS)[number]>("stable");
  const [checking, setChecking]   = useState(false);
  const [checkResult, setCheckResult] = useState<CheckResult | null>(null);

  const [overlayChecking, setOverlayChecking] = useState(false);
  const [overlayCheckResult, setOverlayCheckResult] = useState<OverlayCheckResult | null>(null);

  async function load() {
    try {
      const r = await fetch("/api/admin/updates/status");
      if (r.ok) {
        setStatus(await r.json());
        setRestarting(false);
      }
    } catch {
      // Expected mid-update: the update script restarts this very server.
      setRestarting(true);
    } finally {
      setLoading(false);
    }
  }

  async function loadChannel() {
    const r = await fetch("/api/admin/updates/channel");
    if (r.ok) setChannelState((await r.json()).channel);
  }

  useEffect(() => {
    load();
    loadChannel();
    return () => { if (pollRef.current) clearTimeout(pollRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const inProgress = Boolean(status?.progress) || busy || restarting;
    if (!inProgress) return;
    pollRef.current = setTimeout(load, 2000);
    return () => { if (pollRef.current) clearTimeout(pollRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, busy, restarting]);

  async function changeChannel(next: (typeof CHANNELS)[number]) {
    setChannelState(next);
    setCheckResult(null);
    await fetch("/api/admin/updates/channel", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ channel: next }),
    });
  }

  async function checkForUpdates() {
    setError("");
    setChecking(true);
    const r = await fetch("/api/admin/updates/check", { method: "POST" });
    setCheckResult(await r.json());
    setChecking(false);
  }

  async function checkForOverlay() {
    setError("");
    setOverlayChecking(true);
    const r = await fetch("/api/admin/enterprise/overlay/check", { method: "POST" });
    setOverlayCheckResult(await r.json());
    setOverlayChecking(false);
  }

  async function installOverlay() {
    setError("");
    setBusy(true);
    const r = await fetch("/api/admin/enterprise/overlay/install", { method: "POST" });
    if (r.status === 202) {
      setOverlayCheckResult(null);
      load();
    } else {
      const d = await r.json().catch(() => ({}));
      setError(d.error ?? "Failed to start overlay install.");
    }
    setBusy(false);
  }

  async function installOnline() {
    setError("");
    setBusy(true);
    const r = await fetch("/api/admin/updates/install-online", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ allowDowngrade }),
    });
    if (r.status === 202) {
      setCheckResult(null);
      load();
    } else {
      const d = await r.json().catch(() => ({}));
      setError(d.error ?? "Failed to start update.");
    }
    setBusy(false);
  }

  async function install() {
    if (!file) return;
    setError("");
    setBusy(true);
    const formData = new FormData();
    formData.append("file", file);
    formData.append("allowDowngrade", String(allowDowngrade));
    const r = await fetch("/api/admin/updates/upload", { method: "POST", body: formData });
    if (r.status === 202) {
      setFile(null);
      load();
    } else {
      const d = await r.json().catch(() => ({}));
      setError(d.error ?? "Failed to start update.");
    }
    setBusy(false);
  }

  async function rollback(backupId: string) {
    if (!confirm(`Roll back to the version installed before backup ${backupId}? This restores the database and application files from that backup.`)) return;
    setError("");
    setBusy(true);
    const r = await fetch("/api/admin/updates/rollback", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ backupId }),
    });
    if (r.status === 202) load();
    else {
      const d = await r.json().catch(() => ({}));
      setError(d.error ?? "Failed to start rollback.");
    }
    setBusy(false);
  }

  if (!isAdmin) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-16 text-center text-zinc-500">
        <ShieldOff className="mx-auto mb-3 h-8 w-8" />
        Platform admin access required.
      </div>
    );
  }

  const inProgress = Boolean(status?.progress) || restarting;

  return (
    <div className="mx-auto max-w-3xl px-6 py-8 space-y-8">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Updates</h1>
        <p className="text-sm text-zinc-500">
          Check for a hosted update, or install a signed package directly. Either way the app backs
          up the database and application files first, and automatically rolls back if the update
          fails to come back healthy.
        </p>
      </div>

      {error && <p className="text-sm text-red-400">{error}</p>}

      {loading ? (
        <p className="text-sm text-zinc-500">Loading…</p>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
              <p className="text-xs uppercase tracking-normal text-zinc-500">Core Version</p>
              <p className="mt-1 text-2xl font-semibold text-zinc-100">{status?.installedVersion ?? "unknown"}</p>
            </div>
            {status?.delta.applied && (
              <div className="rounded-lg border border-teal-900/50 bg-teal-950/10 p-4">
                <p className="text-xs uppercase tracking-normal text-teal-500">Enterprise Overlay</p>
                <p className="mt-1 text-2xl font-semibold text-teal-200">{status.delta.version}</p>
              </div>
            )}
          </div>

          {inProgress && (
            <div className="rounded-lg border border-teal-700/40 bg-teal-900/20 p-4 space-y-1">
              <p className="text-sm font-medium text-teal-200">
                {restarting ? "Update in progress — waiting for services to restart…" : status?.progress?.message}
              </p>
              {status?.progress && <p className="text-xs text-teal-400/70">stage: {status.progress.stage}</p>}
            </div>
          )}

          {!inProgress && (
            <>
              <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="flex items-center gap-1.5 text-sm font-semibold text-zinc-300">
                    <CloudDownload className="h-4 w-4" /> Check for Updates
                  </h2>
                  <select
                    value={channel}
                    onChange={(e) => changeChannel(e.target.value as (typeof CHANNELS)[number])}
                    className="rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-300"
                  >
                    {CHANNELS.map((c) => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>

                <button
                  onClick={checkForUpdates}
                  disabled={checking}
                  className="flex items-center gap-1.5 rounded border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-50"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${checking ? "animate-spin" : ""}`} />
                  {checking ? "Checking…" : "Check for Updates"}
                </button>

                {checkResult && !checkResult.configured && (
                  <p className="text-xs text-zinc-500">No update server configured for this instance.</p>
                )}
                {checkResult?.configured && !checkResult.ok && (
                  <p className="text-xs text-red-400">{checkResult.error}</p>
                )}
                {checkResult?.configured && checkResult.ok && (
                  <div className="rounded-md border border-zinc-800 bg-zinc-950/60 p-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <p className="text-sm font-medium text-zinc-100">
                        v{checkResult.latest.version}
                        {checkResult.updateAvailable
                          ? <span className="ml-2 rounded-full bg-teal-900/50 px-2 py-0.5 text-xs text-teal-400">Update available</span>
                          : <span className="ml-2 rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-500">Up to date</span>}
                      </p>
                      {checkResult.latest.packageSize ? (
                        <span className="text-xs text-zinc-500">{formatBytes(checkResult.latest.packageSize)}</span>
                      ) : null}
                    </div>
                    {checkResult.latest.releaseNotes && (
                      <p className="whitespace-pre-line text-xs text-zinc-400">{checkResult.latest.releaseNotes}</p>
                    )}
                    <button
                      onClick={installOnline}
                      disabled={busy || (!checkResult.updateAvailable && !allowDowngrade)}
                      className="flex items-center gap-1.5 rounded bg-teal-600 px-3 py-1.5 text-xs text-white hover:bg-teal-500 disabled:opacity-50"
                    >
                      <PackageCheck className="h-3.5 w-3.5" />
                      {busy ? "Starting…" : "Install Update"}
                    </button>
                  </div>
                )}
              </div>

              <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3">
                <h2 className="flex items-center gap-1.5 text-sm font-semibold text-zinc-300">
                  <UploadCloud className="h-4 w-4" /> Offline Update
                </h2>
                <input
                  type="file"
                  accept=".fpk,.tar.gz"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                  className="block w-full text-sm text-zinc-400 file:mr-3 file:rounded file:border-0 file:bg-zinc-800 file:px-3 file:py-1.5 file:text-zinc-200"
                />
                <label className="flex items-center gap-1.5 text-xs text-zinc-500">
                  <input type="checkbox" checked={allowDowngrade} onChange={(e) => setAllowDowngrade(e.target.checked)} />
                  Allow downgrade / reinstall of an equal or older version
                </label>
                <button
                  onClick={install}
                  disabled={!file || busy}
                  className="flex items-center gap-1.5 rounded bg-teal-600 px-3 py-1.5 text-sm text-white hover:bg-teal-500 disabled:opacity-50"
                >
                  <PackageCheck className="h-3.5 w-3.5" />
                  {busy ? "Starting…" : "Install"}
                </button>
              </div>

              <div className="rounded-lg border border-teal-900/50 bg-teal-950/20 p-4 space-y-3">
                <h2 className="flex items-center gap-1.5 text-sm font-semibold text-teal-300">
                  <Sparkles className="h-4 w-4" /> {status?.delta.applied ? "Enterprise Overlay Updates" : "Upgrade to Enterprise"}
                </h2>

                {!status?.licensed ? (
                  <>
                    <p className="text-xs text-zinc-400">
                      {status?.delta.applied
                        ? "License no longer valid — reactivate to continue receiving overlay updates."
                        : "Activate an Enterprise license to unlock Log/PCAP/RAM Analysis, threat intelligence, SIEM integrations, and more — applied in place, no rebuild needed."}
                    </p>
                    <Link
                      href="/enterprise"
                      className="inline-flex items-center gap-1.5 rounded border border-teal-700/50 px-3 py-1.5 text-xs text-teal-300 hover:bg-teal-900/30"
                    >
                      {status?.delta.applied ? "Reactivate license" : "Activate a license"} <ArrowRight className="h-3 w-3" />
                    </Link>
                  </>
                ) : (
                  <>
                    <button
                      onClick={checkForOverlay}
                      disabled={overlayChecking}
                      className="flex items-center gap-1.5 rounded border border-teal-700/50 px-3 py-1.5 text-sm text-teal-300 hover:bg-teal-900/30 disabled:opacity-50"
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${overlayChecking ? "animate-spin" : ""}`} />
                      {overlayChecking ? "Checking…" : status?.delta.applied ? "Check for Overlay Updates" : "Check for Enterprise Overlay"}
                    </button>

                    {overlayCheckResult && !overlayCheckResult.licensed && (
                      <p className="text-xs text-zinc-500">License no longer valid — check Settings → Enterprise.</p>
                    )}
                    {overlayCheckResult?.licensed && !overlayCheckResult.ok && (
                      <p className="text-xs text-red-400">{overlayCheckResult.error}</p>
                    )}
                    {overlayCheckResult?.licensed && overlayCheckResult.ok && (
                      <div className="rounded-md border border-zinc-800 bg-zinc-950/60 p-3 space-y-2">
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-medium text-zinc-100">
                            v{overlayCheckResult.latest.version}
                            {overlayCheckResult.updateAvailable
                              ? <span className="ml-2 rounded-full bg-teal-900/50 px-2 py-0.5 text-xs text-teal-400">Update available</span>
                              : <span className="ml-2 rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-500">Up to date</span>}
                          </p>
                          {overlayCheckResult.latest.packageSize ? (
                            <span className="text-xs text-zinc-500">{formatBytes(overlayCheckResult.latest.packageSize)}</span>
                          ) : null}
                        </div>
                        <p className="text-xs text-zinc-500">Requires Core v{overlayCheckResult.latest.requiresCoreVersion}+</p>
                        {!overlayCheckResult.coreVersionSatisfied && (
                          <p className="text-xs text-red-400">
                            Installed Core (v{status?.installedVersion}) is older than required — install the pending Core update first.
                          </p>
                        )}
                        {overlayCheckResult.latest.releaseNotes && (
                          <p className="whitespace-pre-line text-xs text-zinc-400">{overlayCheckResult.latest.releaseNotes}</p>
                        )}
                        <button
                          onClick={installOverlay}
                          disabled={busy || !overlayCheckResult.coreVersionSatisfied || (!overlayCheckResult.updateAvailable && !allowDowngrade)}
                          className="flex items-center gap-1.5 rounded bg-teal-600 px-3 py-1.5 text-xs text-white hover:bg-teal-500 disabled:opacity-50"
                        >
                          <PackageCheck className="h-3.5 w-3.5" />
                          {busy ? "Starting…" : status?.delta.applied ? "Install Overlay Update" : "Apply Enterprise Overlay"}
                        </button>
                      </div>
                    )}
                  </>
                )}
              </div>
            </>
          )}

          <div className="space-y-3">
            <h2 className="text-sm font-semibold text-zinc-300">Version History</h2>
            {!status?.backups.length ? (
              <p className="text-sm text-zinc-600">No updates have been installed yet.</p>
            ) : (
              <div className="overflow-hidden rounded-lg border border-zinc-800">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-zinc-800 bg-zinc-900 text-left text-xs text-zinc-500">
                      <th className="px-3 py-2 font-medium">From</th>
                      <th className="px-3 py-2 font-medium">To</th>
                      <th className="px-3 py-2 font-medium">Date</th>
                      <th className="px-3 py-2 font-medium">Status</th>
                      <th className="px-3 py-2 font-medium">Rollback</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800">
                    {status.backups.map(({ manifest, result }) => (
                      <tr key={manifest.id} className="bg-zinc-950">
                        <td className="px-3 py-2 text-zinc-400">{manifest.fromVersion}</td>
                        <td className="px-3 py-2 text-zinc-200">{manifest.toVersion}</td>
                        <td className="px-3 py-2 text-zinc-500 text-xs">{new Date(manifest.createdAt).toLocaleString()}</td>
                        <td className="px-3 py-2 text-xs">
                          {!result ? (
                            <span className="text-zinc-600">pending</span>
                          ) : result.success ? (
                            <span className="text-teal-400">{result.rolledBack ? "rolled back" : "success"}</span>
                          ) : (
                            <span className="text-red-400">failed{result.error ? `: ${result.error}` : ""}</span>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          {!inProgress && (
                            <button
                              onClick={() => rollback(manifest.id)}
                              disabled={busy}
                              className="flex items-center gap-1 text-xs text-zinc-400 hover:text-zinc-200 disabled:opacity-50"
                            >
                              <Undo2 className="h-3 w-3" /> Restore this backup
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
