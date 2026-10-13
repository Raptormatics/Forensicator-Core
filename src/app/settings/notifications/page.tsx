"use client";

import { useCallback, useEffect, useState } from "react";
import { ArrowLeft, Bell, CheckCircle2, AlertCircle, Loader2 } from "lucide-react";
import Link from "next/link";

// Core has no RBAC — the sole user always has full access, same as every
// other instance-level settings page.

type NotificationSettings = {
  criticalFindingAlertsEnabled: boolean;
  notificationEmail: string | null;
  smtpHost: string | null;
  smtpPort: number;
  smtpUser: string | null;
  smtpPasswordLast4: string | null;
  hasSmtpPassword: boolean;
  smtpFromAddress: string | null;
  smtpSecure: boolean;
};

export default function NotificationSettingsPage() {
  const [settings, setSettings] = useState<NotificationSettings | null>(null);
  const [smtpPasswordInput, setSmtpPasswordInput] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; error?: string } | null>(null);

  const loadSettings = useCallback(async () => {
    const r = await fetch("/api/settings/notifications");
    if (r.ok) setSettings(await r.json());
    setLoading(false);
  }, []);

  useEffect(() => { loadSettings(); }, [loadSettings]);

  async function saveSettings() {
    if (!settings) return;
    setError(""); setSaved(false); setSaving(true);
    try {
      const body: Record<string, unknown> = {
        criticalFindingAlertsEnabled: settings.criticalFindingAlertsEnabled,
        notificationEmail: settings.notificationEmail ?? "",
        smtpHost: settings.smtpHost ?? "",
        smtpPort: settings.smtpPort,
        smtpUser: settings.smtpUser ?? "",
        smtpFromAddress: settings.smtpFromAddress ?? "",
        smtpSecure: settings.smtpSecure,
      };
      if (smtpPasswordInput.trim()) body.smtpPassword = smtpPasswordInput.trim();
      const r = await fetch("/api/settings/notifications", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await r.json();
      if (!r.ok) { setError(data.error ?? "Failed to save settings."); return; }
      setSettings(data);
      setSmtpPasswordInput("");
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch {
      setError("Failed to save settings.");
    } finally {
      setSaving(false);
    }
  }

  async function sendTestEmail() {
    if (!settings?.notificationEmail) return;
    setTesting(true); setTestResult(null);
    try {
      const r = await fetch("/api/settings/notifications/test", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: settings.notificationEmail,
          smtpHost: settings.smtpHost || undefined,
          smtpPort: settings.smtpPort || undefined,
          smtpUser: settings.smtpUser || undefined,
          smtpPassword: smtpPasswordInput.trim() || undefined,
          smtpFromAddress: settings.smtpFromAddress || undefined,
          smtpSecure: settings.smtpSecure,
        }),
      });
      setTestResult(await r.json());
    } catch {
      setTestResult({ ok: false, error: "Request failed." });
    } finally {
      setTesting(false);
    }
  }

  if (loading || !settings) {
    return <div className="p-8 text-zinc-500">Loading…</div>;
  }

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-6">
      <Link href="/settings" className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300">
        <ArrowLeft className="h-4 w-4" /> Settings
      </Link>

      <div className="flex items-center gap-2">
        <Bell className="h-5 w-5 text-teal-400" />
        <h1 className="text-xl font-semibold text-zinc-100">Critical Finding Alerts</h1>
      </div>
      <p className="text-sm text-zinc-500">
        Send an email whenever a critical-severity finding is created, across Investigation uploads, Log Analysis,
        PCAP Analysis, and RAM Analysis. One batched email per processing run — not one per finding.
      </p>

      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-950/20 border border-red-900/40 rounded-lg px-3 py-2">
          <AlertCircle className="h-4 w-4 shrink-0" /> {error}
        </div>
      )}

      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 space-y-5">
        <label className="flex items-center gap-2.5">
          <input
            type="checkbox"
            checked={settings.criticalFindingAlertsEnabled}
            onChange={(e) => setSettings({ ...settings, criticalFindingAlertsEnabled: e.target.checked })}
            className="rounded border-zinc-700 bg-zinc-950 accent-teal-500"
          />
          <span className="text-sm text-zinc-200">Enable critical finding alerts</span>
        </label>

        <div className="space-y-1.5">
          <label className="block text-xs text-zinc-400">Recipient email</label>
          <input
            type="email"
            value={settings.notificationEmail ?? ""}
            onChange={(e) => setSettings({ ...settings, notificationEmail: e.target.value })}
            placeholder="analyst@example.com"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30"
          />
        </div>

        <div className="border-t border-zinc-800 pt-4 space-y-4">
          <h2 className="text-sm font-semibold text-zinc-300">SMTP Server</h2>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="sm:col-span-2 space-y-1.5">
              <label className="block text-xs text-zinc-400">Host</label>
              <input
                type="text"
                value={settings.smtpHost ?? ""}
                onChange={(e) => setSettings({ ...settings, smtpHost: e.target.value })}
                placeholder="smtp.example.com"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs text-zinc-400">Port</label>
              <input
                type="number"
                value={settings.smtpPort}
                onChange={(e) => setSettings({ ...settings, smtpPort: Number(e.target.value) || 587 })}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <label className="block text-xs text-zinc-400">Username</label>
              <input
                type="text"
                value={settings.smtpUser ?? ""}
                onChange={(e) => setSettings({ ...settings, smtpUser: e.target.value })}
                placeholder="alerts@example.com"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs text-zinc-400">
                Password {settings.hasSmtpPassword && <span className="text-zinc-600">(saved, ending •••{settings.smtpPasswordLast4})</span>}
              </label>
              <input
                type="password"
                value={smtpPasswordInput}
                onChange={(e) => setSmtpPasswordInput(e.target.value)}
                placeholder={settings.hasSmtpPassword ? "Leave blank to keep current password" : ""}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs text-zinc-400">From address</label>
            <input
              type="text"
              value={settings.smtpFromAddress ?? ""}
              onChange={(e) => setSettings({ ...settings, smtpFromAddress: e.target.value })}
              placeholder="Forensicator Alerts <alerts@example.com>"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30"
            />
          </div>

          <label className="flex items-center gap-2.5">
            <input
              type="checkbox"
              checked={settings.smtpSecure}
              onChange={(e) => setSettings({ ...settings, smtpSecure: e.target.checked })}
              className="rounded border-zinc-700 bg-zinc-950 accent-teal-500"
            />
            <span className="text-sm text-zinc-200">Use TLS (port 465)</span>
          </label>
        </div>

        <div className="flex items-center gap-3 border-t border-zinc-800 pt-4">
          <button
            onClick={saveSettings}
            disabled={saving}
            className="flex items-center gap-2 rounded-lg bg-teal-700 px-4 py-2 text-sm font-semibold text-white hover:bg-teal-600 disabled:opacity-60"
          >
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            {saved && <CheckCircle2 className="h-4 w-4" />}
            {saving ? "Saving…" : saved ? "Saved" : "Save changes"}
          </button>
          <button
            onClick={sendTestEmail}
            disabled={testing || !settings.notificationEmail}
            className="flex items-center gap-2 rounded-lg border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-300 hover:border-zinc-600 disabled:opacity-50"
          >
            {testing && <Loader2 className="h-4 w-4 animate-spin" />}
            Send test email
          </button>
        </div>

        {testResult && (
          <div className={`flex items-center gap-2 text-sm rounded-lg px-3 py-2 ${testResult.ok ? "text-teal-300 bg-teal-950/20 border border-teal-900/40" : "text-red-400 bg-red-950/20 border border-red-900/40"}`}>
            {testResult.ok ? <CheckCircle2 className="h-4 w-4 shrink-0" /> : <AlertCircle className="h-4 w-4 shrink-0" />}
            {testResult.ok ? "Test email sent." : (testResult.error ?? "Test email failed.")}
          </div>
        )}
      </div>
    </div>
  );
}
