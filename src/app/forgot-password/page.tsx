"use client";

import { useState } from "react";
import { Shield, Mail, ArrowLeft, CheckCircle2 } from "lucide-react";
import Link from "next/link";

export default function ForgotPasswordPage() {
  const [email,   setEmail]   = useState("");
  const [loading, setLoading] = useState(false);
  const [sent,    setSent]    = useState(false);
  const [error,   setError]   = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim().toLowerCase() }),
      });
      if (res.ok) {
        setSent(true);
      } else {
        const d = await res.json();
        setError(d.error ?? "Something went wrong.");
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
          <h1 className="text-xl font-bold text-zinc-100">Reset Password</h1>
          <p className="text-sm text-zinc-500 text-center">
            Enter your email address and we&apos;ll send you a reset link.
          </p>
        </div>

        {sent ? (
          <div className="flex flex-col items-center gap-4 rounded-lg border border-teal-800 bg-teal-950/40 p-6">
            <CheckCircle2 className="h-8 w-8 text-teal-400" />
            <p className="text-sm text-zinc-300 text-center">
              If an account exists for <strong className="text-zinc-100">{email}</strong>, a reset link has been sent.
            </p>
            <Link href="/login" className="text-sm text-teal-500 hover:text-teal-400 flex items-center gap-1">
              <ArrowLeft className="h-3.5 w-3.5" /> Back to sign in
            </Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <p className="rounded-lg border border-red-900 bg-red-950/50 px-4 py-3 text-sm text-red-400">{error}</p>
            )}
            <div className="space-y-1">
              <label className="block text-xs font-medium text-zinc-400">Email address</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
                <input
                  type="email" required value={email} onChange={e => setEmail(e.target.value)}
                  placeholder="analyst@example.com"
                  className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2.5 pl-10 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none"
                />
              </div>
            </div>
            <button
              type="submit" disabled={loading}
              className="w-full rounded-lg bg-teal-700 py-2.5 text-sm font-semibold text-white hover:bg-teal-600 disabled:opacity-60"
            >
              {loading ? "Sending…" : "Send reset link"}
            </button>
            <div className="text-center">
              <Link href="/login" className="text-sm text-zinc-500 hover:text-zinc-300 flex items-center justify-center gap-1">
                <ArrowLeft className="h-3.5 w-3.5" /> Back to sign in
              </Link>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
