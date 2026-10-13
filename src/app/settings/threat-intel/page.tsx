"use client";
import { useEffect, useState, useRef, Suspense } from "react";
import { useSession } from "next-auth/react";
import { useSearchParams } from "next/navigation";
import { KeyRound, Radio, RefreshCw, ShieldOff, Trash2 } from "lucide-react";

interface ProviderStatus {
  provider: string;
  requiresKey: boolean;
  enabled: boolean;
  configured: boolean;
  usingGlobalFallback: boolean;
  keyLast4: string | null;
  lastUsedAt: string | null;
  lastError: string | null;
}

const LABEL: Record<string, string> = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  otx: "OTX AlienVault",
  urlhaus: "URLhaus",
  threatfox: "ThreatFox",
  malwarebazaar: "MalwareBazaar",
};


function ThreatIntelSettings() {
  const { data: session } = useSession();
  // Core is single-user/single-role — the sole account always has full access.
  const isAdmin = true;
  const focusProvider = useSearchParams().get("provider");

  const [providers, setProviders] = useState<ProviderStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [noOrg, setNoOrg] = useState(false);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<string | null>(null);
  const [error, setError] = useState("");
  const cardRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const inputRefs = useRef<Record<string, HTMLInputElement | null>>({});

  // URLhaus is the only free feed with a local bulk-cache to refresh — see
  // src/lib/intelligence/urlhaus-feed.ts. Core syncs it manually only
  // (POST /api/intelligence/urlhaus-sync, no schedule); the Enterprise
  // overlay restores a 6-hour auto-sync on top of this same action.
  // ThreatFox and MalwareBazaar are plain per-value live API lookups, same
  // as VirusTotal/AbuseIPDB/OTX — no feed to sync, so no button for them.
  const [feedStatus, setFeedStatus] = useState<{ lastSyncedAt: string | null; totalEntries: number } | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    const r = await fetch("/api/threat-intel/providers");
    if (r.status === 400) { setNoOrg(true); setLoading(false); return; }
    if (r.ok) setProviders((await r.json()).providers ?? []);
    setLoading(false);
  }

  async function loadFeedStatus() {
    const r = await fetch("/api/intelligence/urlhaus-sync");
    if (r.ok) setFeedStatus(await r.json());
  }

  async function syncUrlhausFeed() {
    setSyncing(true);
    setSyncMsg(null);
    try {
      const r = await fetch("/api/intelligence/urlhaus-sync", { method: "POST" });
      const d = await r.json().catch(() => ({}));
      setSyncMsg(r.ok ? `Synced — ${d.added} new indicator${d.added !== 1 ? "s" : ""} of ${d.total} total in the feed.` : (d.message ?? "Sync failed."));
      if (r.ok) loadFeedStatus();
    } catch {
      setSyncMsg("Sync failed — check your connection.");
    } finally {
      setSyncing(false);
    }
  }

  function formatLastSynced(value: string | null): string {
    if (!value) return "Never synced";
    return `Last synced ${new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value))}`;
  }

  useEffect(() => { load(); loadFeedStatus(); }, []);

  // Deep-link support for "Configure"/"Add Key" buttons elsewhere (e.g. the
  // Threat Intelligence dashboard's provider cards) — jump straight to and
  // briefly highlight the requested provider's card instead of leaving the
  // user to hunt for it in this list.
  useEffect(() => {
    if (!focusProvider || loading) return;
    const el = cardRefs.current[focusProvider];
    if (!el) return;
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.classList.add("ring-2", "ring-teal-500");
    inputRefs.current[focusProvider]?.focus();
    const t = setTimeout(() => el.classList.remove("ring-2", "ring-teal-500"), 2500);
    return () => clearTimeout(t);
  }, [focusProvider, loading]);

  async function save(provider: string) {
    const apiKey = drafts[provider]?.trim();
    if (!apiKey) return;
    setError("");
    setSaving(provider);
    const r = await fetch("/api/threat-intel/providers", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ provider, apiKey }),
    });
    const d = await r.json();
    if (r.ok) { setProviders(d.providers); setDrafts((s) => ({ ...s, [provider]: "" })); }
    else setError(d.error ?? "Failed to save key.");
    setSaving(null);
  }

  async function toggle(provider: string, enabled: boolean) {
    setError("");
    setSaving(provider);
    const r = await fetch("/api/threat-intel/providers", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ provider, enabled }),
    });
    const d = await r.json();
    if (r.ok) setProviders(d.providers);
    else setError(d.error ?? "Failed to update.");
    setSaving(null);
  }

  async function remove(provider: string) {
    if (!confirm(`Reset ${LABEL[provider]} to its default state for your organization?`)) return;
    setSaving(provider);
    const r = await fetch(`/api/threat-intel/providers?provider=${provider}`, { method: "DELETE" });
    if (r.ok) setProviders((await r.json()).providers);
    setSaving(null);
  }

  if (noOrg) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-16 text-center text-zinc-500">
        <ShieldOff className="mx-auto mb-3 h-8 w-8" />
        No organization associated with your account.
      </div>
    );
  }

  const keyed = providers.filter((p) => p.requiresKey);
  const keyless = providers.filter((p) => !p.requiresKey);

  return (
    <div className="mx-auto max-w-3xl px-6 py-8 space-y-8">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Threat Intel Providers</h1>
        <p className="text-sm text-zinc-500">
          Manage every enrichment provider available to your organization — including the free
          feeds, which are enabled by default but can be turned off here.
        </p>
      </div>

      {error && <p className="text-sm text-red-400">{error}</p>}

      {loading ? (
        <p className="text-sm text-zinc-500">Loading…</p>
      ) : (
        <>
          <section className="space-y-4">
            <h2 className="text-sm font-semibold text-zinc-300">API-key providers</h2>
            {keyed.map((p) => (
              <div
                key={p.provider}
                ref={(el) => { cardRefs.current[p.provider] = el; }}
                className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3 transition-shadow"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <KeyRound className="h-4 w-4 text-zinc-500" />
                    <span className="font-medium text-zinc-200">{LABEL[p.provider]}</span>
                    {p.configured ? (
                      <span className={`rounded-full px-2 py-0.5 text-xs ${p.enabled ? "bg-teal-900/50 text-teal-400" : "bg-zinc-800 text-zinc-500"}`}>
                        {p.enabled ? "Active" : "Disabled"} · ••••{p.keyLast4}
                      </span>
                    ) : p.usingGlobalFallback ? (
                      <span className="rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">
                        {p.enabled ? "Using deployment default" : "Disabled"}
                      </span>
                    ) : (
                      <span className="rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-500">Not configured</span>
                    )}
                  </div>
                  {isAdmin && (p.configured || p.usingGlobalFallback) && (
                    <div className="flex items-center gap-3">
                      <label className="flex items-center gap-1.5 text-xs text-zinc-500">
                        <input type="checkbox" checked={p.enabled} disabled={saving === p.provider}
                          onChange={(e) => toggle(p.provider, e.target.checked)} />
                        Enabled
                      </label>
                      {p.configured && (
                        <button onClick={() => remove(p.provider)} disabled={saving === p.provider} title="Remove key" className="text-zinc-600 hover:text-red-400">
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  )}
                </div>

                {p.lastError && <p className="text-xs text-red-400">Last error: {p.lastError}</p>}

                {isAdmin && (
                  <div className="flex gap-2">
                    <input
                      ref={(el) => { inputRefs.current[p.provider] = el; }}
                      type="password"
                      value={drafts[p.provider] ?? ""}
                      onChange={(e) => setDrafts((s) => ({ ...s, [p.provider]: e.target.value }))}
                      placeholder={p.configured ? "Replace key…" : "Enter API key…"}
                      className="flex-1 rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500"
                    />
                    <button
                      onClick={() => save(p.provider)}
                      disabled={saving === p.provider || !drafts[p.provider]?.trim()}
                      className="rounded bg-teal-600 px-3 py-1.5 text-sm text-white hover:bg-teal-500 disabled:opacity-50"
                    >
                      {saving === p.provider ? "Saving…" : "Save"}
                    </button>
                  </div>
                )}

                {/* The bulk csv_recent feed download stays key-free even though
                    the per-value API above it now requires an Auth-Key — two
                    independent mechanisms under the same provider card. */}
                {p.provider === "urlhaus" && (
                  <div className="flex items-center justify-between border-t border-zinc-800 pt-2">
                    <span className="text-xs text-zinc-500">
                      {formatLastSynced(feedStatus?.lastSyncedAt ?? null)}
                      {feedStatus && feedStatus.totalEntries > 0 && ` · ${feedStatus.totalEntries.toLocaleString()} cached indicators`}
                    </span>
                    {isAdmin && (
                      <button
                        onClick={syncUrlhausFeed}
                        disabled={syncing}
                        title="Refresh the local URLhaus feed cache used for free, automatic URL matching"
                        className="flex items-center gap-1.5 rounded-md border border-zinc-800 px-2.5 py-1 text-xs text-zinc-400 hover:text-zinc-200 hover:border-zinc-600 disabled:opacity-50"
                      >
                        <RefreshCw className={`h-3 w-3 ${syncing ? "animate-spin" : ""}`} /> {syncing ? "Syncing…" : "Sync Now"}
                      </button>
                    )}
                  </div>
                )}
                {p.provider === "urlhaus" && syncMsg && (
                  <p className="text-xs text-zinc-500">{syncMsg}</p>
                )}
              </div>
            ))}
          </section>

          <section className="space-y-4">
            <h2 className="text-sm font-semibold text-zinc-300">Free feeds (no key required)</h2>
            {keyless.map((p) => (
              <div key={p.provider} className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Radio className="h-4 w-4 text-zinc-500" />
                    <span className="font-medium text-zinc-200">{LABEL[p.provider]}</span>
                    <span className={`rounded-full px-2 py-0.5 text-xs ${p.enabled ? "bg-teal-900/50 text-teal-400" : "bg-zinc-800 text-zinc-500"}`}>
                      {p.enabled ? "Active" : "Disabled"}
                    </span>
                  </div>
                  {isAdmin && (
                    <label className="flex items-center gap-1.5 text-xs text-zinc-500">
                      <input type="checkbox" checked={p.enabled} disabled={saving === p.provider}
                        onChange={(e) => toggle(p.provider, e.target.checked)} />
                      Enabled
                    </label>
                  )}
                </div>
              </div>
            ))}
          </section>
        </>
      )}
    </div>
  );
}

export default function ThreatIntelSettingsPage() {
  return (
    <Suspense>
      <ThreatIntelSettings />
    </Suspense>
  );
}
