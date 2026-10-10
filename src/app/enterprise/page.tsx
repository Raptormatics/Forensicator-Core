"use client";

import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import {
  Sparkles,
  KeyRound,
  Mail,
  ExternalLink,
  ArrowUpCircle,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Container,
} from "lucide-react";

// Mirrors isInstanceAdmin() (src/lib/auth/session.ts) — Core is always
// appliance mode, so org_admin manages this too, same tier as Updates.
const ADMIN_ROLES = ["platform_admin", "org_admin"];
// A valid license only ever unlocks installing the overlay under
// Settings -> Updates — which is unconditionally blocked in Docker (no
// sudo/systemd for the installer). Activating one here anyway would be
// a dead end, so the whole form is replaced with an explanation instead.
// Matching server-side guard: src/lib/updates/container-guard.ts.
const IS_CONTAINERIZED = process.env.NEXT_PUBLIC_DEPLOYMENT_CONTAINER === "docker";

type ActivationState = {
  valid: boolean;
  reason: string;
  configured: boolean;
  licenseId: string | null;
  customerName: string | null;
  licenseType: string | null;
  plan: string | null;
  expiresAt: string | null;
};

export default function EnterprisePage() {
  const { data: session } = useSession();
  const isAdmin = ADMIN_ROLES.includes(session?.user?.role ?? "");

  const [state, setState] = useState<ActivationState | null>(null);
  const [loading, setLoading] = useState(true);
  const [licText, setLicText] = useState("");
  const [activating, setActivating] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    const r = await fetch("/api/admin/enterprise/license");
    if (r.ok) setState(await r.json());
    setLoading(false);
  }

  useEffect(() => { if (isAdmin) load(); else setLoading(false); }, [isAdmin]);

  async function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setLicText(await file.text());
  }

  async function activate() {
    if (!licText.trim()) return;
    setError("");
    setActivating(true);
    const r = await fetch("/api/admin/enterprise/license", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ licContent: licText.trim() }),
    });
    const data = await r.json();
    if (!r.ok) {
      setError(data.error ?? "Activation failed.");
    } else {
      setState(data);
      setLicText("");
    }
    setActivating(false);
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-8 space-y-8">
      <div className="flex items-center gap-3">
        <Sparkles className="h-5 w-5 text-teal-400" />
        <div>
          <h1 className="text-xl font-bold text-zinc-100">Forensicator Enterprise</h1>
          <p className="text-sm text-zinc-500">
            Everything in Forensicator Core, plus Log/PCAP/RAM Analysis, threat intelligence, SIEM
            integrations, and more — for teams that need the full platform.
          </p>
        </div>
      </div>

      <div className="rounded-xl border border-teal-900/50 bg-teal-950/20 p-5 space-y-4">
        <div className="flex items-center gap-2">
          <ArrowUpCircle className="h-4 w-4 text-teal-400" />
          <h2 className="text-sm font-semibold text-zinc-200">Upgrading from Core</h2>
        </div>
        <p className="text-sm text-zinc-400">
          Forensicator Enterprise is a signed, in-place overlay on top of Core — upgrading doesn&apos;t
          require tearing down or rebuilding your existing instance. Your data, users, and
          investigations all carry over as-is.
        </p>
        <div className="flex flex-wrap items-center gap-3 pt-1">
          <a
            href="https://forensicator.io/enterprise"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 rounded-lg bg-teal-700 px-4 py-2 text-sm font-semibold text-white hover:bg-teal-600"
          >
            Learn more
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
          <a
            href="mailto:hello@forensicator.io"
            className="flex items-center gap-2 rounded-lg border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-300 hover:border-teal-700/50 hover:text-teal-300"
          >
            <Mail className="h-3.5 w-3.5" />
            hello@forensicator.io
          </a>
        </div>
      </div>

      {isAdmin && !loading && IS_CONTAINERIZED && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 space-y-3">
          <div className="flex items-center gap-2">
            <Container className="h-4 w-4 text-zinc-400" />
            <h2 className="text-sm font-semibold text-zinc-200">Not available in Docker</h2>
          </div>
          <p className="text-sm text-zinc-500">
            Enterprise isn&apos;t available in the Docker deployment — applying the overlay needs
            sudo/systemd this container doesn&apos;t have, so license activation is disabled here
            too (it would only ever unlock a feature this instance can&apos;t use). Enterprise on
            Docker requires its own Enterprise Docker image, built separately from Core&apos;s —
            contact <a href="mailto:hello@forensicator.io" className="text-teal-400 hover:text-teal-300">hello@forensicator.io</a> if that&apos;s what you need.
          </p>
        </div>
      )}

      {isAdmin && !loading && !IS_CONTAINERIZED && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 space-y-4">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-teal-400" />
            <h2 className="text-sm font-semibold text-zinc-200">License Activation</h2>
          </div>

          {state?.configured && (
            <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-sm ${
              state.valid ? "border-teal-900/50 bg-teal-950/20 text-teal-300" : "border-red-900/50 bg-red-950/20 text-red-400"
            }`}>
              {state.valid ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> : <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />}
              <div>
                <p className="font-medium">{state.reason}</p>
                {state.customerName && (
                  <p className="mt-0.5 text-xs opacity-80">
                    {state.customerName} · {state.plan} · {state.licenseType}
                    {state.expiresAt && ` · expires ${new Date(state.expiresAt).toLocaleDateString()}`}
                  </p>
                )}
              </div>
            </div>
          )}

          {state?.valid ? (
            <p className="text-sm text-zinc-500">
              A valid license is active. Head to{" "}
              <a href="/settings/updates" className="text-teal-400 hover:text-teal-300">Settings → Updates</a>{" "}
              to install the Enterprise overlay.
            </p>
          ) : (
            <>
              <p className="text-xs text-zinc-500">
                Upload or paste the .lic file you received when purchasing Enterprise. This only
                unlocks installing the overlay under Settings → Updates — it doesn&apos;t install
                anything by itself.
              </p>
              {error && <p className="text-sm text-red-400">{error}</p>}
              <input
                type="file"
                accept=".lic,text/plain"
                onChange={handleFile}
                className="block w-full text-sm text-zinc-400 file:mr-3 file:rounded file:border-0 file:bg-zinc-800 file:px-3 file:py-1.5 file:text-zinc-200"
              />
              <textarea
                value={licText}
                onChange={(e) => setLicText(e.target.value)}
                placeholder="…or paste the .lic file's contents here"
                rows={3}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs font-mono text-zinc-300 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30"
              />
              <button
                onClick={activate}
                disabled={!licText.trim() || activating}
                className="flex items-center gap-2 rounded-lg bg-teal-700 px-4 py-2 text-sm font-semibold text-white hover:bg-teal-600 disabled:opacity-50"
              >
                {activating && <Loader2 className="h-4 w-4 animate-spin" />}
                {activating ? "Activating…" : "Activate License"}
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
