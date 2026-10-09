"use client";

import { useEffect, useState } from "react";
import { Suspense } from "react";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield, AlertCircle, Loader2, Eye, EyeOff, ArrowLeft } from "lucide-react";
import Link from "next/link";

const SSO_ERROR_MESSAGES: Record<string, string> = {
  sso_unavailable: "Single sign-on isn't available for that account right now. Try signing in with your password instead.",
  sso_no_account: "No account was found for that Microsoft sign-in. Ask your organization admin to create one.",
  sso_cancelled: "Sign-in was cancelled.",
};

function LoginForm() {
  const router       = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl  = searchParams.get("callbackUrl") ?? "/dashboard";

  const [step,     setStep]     = useState<"email" | "password" | "sso">("email");
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [showPw,   setShowPw]   = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");

  useEffect(() => {
    const ssoError = searchParams.get("error");
    if (ssoError && SSO_ERROR_MESSAGES[ssoError]) setError(SSO_ERROR_MESSAGES[ssoError]);
  }, [searchParams]);

  async function handleContinue(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    const trimmed = email.trim().toLowerCase();
    if (!trimmed) return;

    setLoading(true);
    try {
      const r = await fetch("/api/auth/sso/lookup", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: trimmed }),
      });
      const d = r.ok ? await r.json() : { ssoAvailable: false };
      setStep(d.ssoAvailable ? "sso" : "password");
    } catch {
      setStep("password");
    } finally {
      setLoading(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    const result = await signIn("credentials", {
      redirect: false,
      email:    email.trim().toLowerCase(),
      password,
    });

    setLoading(false);

    if (result?.error) {
      setError(
        result.error === "CredentialsSignin"
          ? "Invalid email or password. Please try again."
          : result.error
      );
    } else {
      router.push(callbackUrl);
      router.refresh();
    }
  }

  function backToEmail() {
    setError("");
    setPassword("");
    setStep("email");
  }

  const ssoStartUrl =
    `/api/auth/sso/entra/start?email=${encodeURIComponent(email.trim().toLowerCase())}` +
    `&callbackUrl=${encodeURIComponent(callbackUrl)}`;

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <div className="w-full max-w-sm space-y-8">
        {/* Logo */}
        <div className="flex flex-col items-center gap-2">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-teal-900/50 ring-1 ring-teal-700">
            <Shield className="h-6 w-6 text-teal-400" />
          </div>
          <h1 className="text-xl font-bold text-zinc-100">Forensicator Enterprise</h1>
          <p className="text-sm text-zinc-500">Sign in to your account</p>
        </div>

        {error && (
          <div className="flex items-center gap-2 rounded-lg border border-red-900 bg-red-950/50 px-4 py-3">
            <AlertCircle className="h-4 w-4 shrink-0 text-red-400" />
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {step === "email" && (
          <form onSubmit={handleContinue} className="space-y-4">
            <div className="space-y-1">
              <label className="block text-xs font-medium text-zinc-400">Email address</label>
              <input
                type="email"
                required
                autoFocus
                autoComplete="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="analyst@example.com"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2.5 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-teal-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-teal-600 disabled:opacity-60"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? "Checking…" : "Continue"}
            </button>
          </form>
        )}

        {step === "sso" && (
          <div className="space-y-4">
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2.5 text-sm text-zinc-400">
              {email.trim()}
            </div>
            <a
              href={ssoStartUrl}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-zinc-700 bg-zinc-100 px-4 py-2.5 text-sm font-semibold text-zinc-900 hover:bg-white"
            >
              Continue with Microsoft
            </a>
            <button
              type="button"
              onClick={backToEmail}
              className="flex w-full items-center justify-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300"
            >
              <ArrowLeft className="h-3 w-3" /> Use a different email
            </button>
          </div>
        )}

        {step === "password" && (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <label className="block text-xs font-medium text-zinc-400">Email address</label>
                <button type="button" onClick={backToEmail} className="text-xs text-zinc-500 hover:text-zinc-300">
                  Change
                </button>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2.5 text-sm text-zinc-400">
                {email.trim()}
              </div>
            </div>

            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <label className="block text-xs font-medium text-zinc-400">Password</label>
                <Link href="/forgot-password" className="text-xs text-teal-500 hover:text-teal-400">
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <input
                  type={showPw ? "text" : "password"}
                  required
                  autoFocus
                  autoComplete="current-password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2.5 pr-10 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30"
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                >
                  {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-teal-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-teal-600 disabled:opacity-60"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? "Signing in…" : "Sign in"}
            </button>
          </form>
        )}

        <p className="text-center text-xs text-zinc-600">
          Forensicator Enterprise — DFIR Platform
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
