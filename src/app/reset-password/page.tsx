"use client";

import { useState, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { Shield, Eye, EyeOff, CheckCircle2 } from "lucide-react";
import Link from "next/link";

function ResetForm() {
  const searchParams = useSearchParams();
  const router       = useRouter();
  const token        = searchParams.get("token") ?? "";

  const [password,  setPassword]  = useState("");
  const [confirm,   setConfirm]   = useState("");
  const [showPw,    setShowPw]    = useState(false);
  const [loading,   setLoading]   = useState(false);
  const [done,      setDone]      = useState(false);
  const [error,     setError]     = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (password !== confirm) { setError("Passwords do not match."); return; }
    if (password.length < 8)  { setError("Password must be at least 8 characters."); return; }
    setLoading(true);
    try {
      const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      if (res.ok) {
        setDone(true);
        setTimeout(() => router.push("/login"), 3000);
      } else {
        const d = await res.json();
        setError(d.error ?? "Reset failed. Link may be expired.");
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <div className="w-full max-w-sm space-y-8">
        <div className="flex flex-col items-center gap-2">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-teal-900/50 ring-1 ring-teal-700">
            <Shield className="h-6 w-6 text-teal-400" />
          </div>
          <h1 className="text-xl font-bold text-zinc-100">Set New Password</h1>
        </div>

        {done ? (
          <div className="flex flex-col items-center gap-4 rounded-lg border border-teal-800 bg-teal-950/40 p-6">
            <CheckCircle2 className="h-8 w-8 text-teal-400" />
            <p className="text-sm text-zinc-300 text-center">Password updated. Redirecting to sign in…</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {!token && (
              <p className="rounded-lg border border-red-900 bg-red-950/50 px-4 py-3 text-sm text-red-400">
                Invalid or missing reset token.{" "}
                <Link href="/forgot-password" className="underline">Request a new link.</Link>
              </p>
            )}
            {error && (
              <p className="rounded-lg border border-red-900 bg-red-950/50 px-4 py-3 text-sm text-red-400">{error}</p>
            )}
            <div className="space-y-1">
              <label className="block text-xs font-medium text-zinc-400">New password</label>
              <div className="relative">
                <input
                  type={showPw ? "text" : "password"} required value={password}
                  onChange={e => setPassword(e.target.value)} minLength={8}
                  placeholder="Minimum 8 characters"
                  className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2.5 pr-10 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none"
                />
                <button type="button" onClick={() => setShowPw(v => !v)} className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500">
                  {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>
            <div className="space-y-1">
              <label className="block text-xs font-medium text-zinc-400">Confirm password</label>
              <input
                type="password" required value={confirm} onChange={e => setConfirm(e.target.value)}
                placeholder="Repeat password"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2.5 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none"
              />
            </div>
            <button type="submit" disabled={loading || !token}
              className="w-full rounded-lg bg-teal-700 py-2.5 text-sm font-semibold text-white hover:bg-teal-600 disabled:opacity-60">
              {loading ? "Updating…" : "Update password"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return <Suspense><ResetForm /></Suspense>;
}
