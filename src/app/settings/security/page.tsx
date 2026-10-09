"use client";

import { useEffect, useState } from "react";
import { ShieldCheck, Clock, LogIn, AlertCircle, CheckCircle2 } from "lucide-react";
import Link from "next/link";

interface SecurityInfo {
  lastLogin: string | null;
  loginHistory: { createdAt: string; actorIp: string | null; result: string }[];
}

export default function SecurityPage() {
  const [info,    setInfo]    = useState<SecurityInfo | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch("/api/auth/profile").then(r => r.json()),
      fetch("/api/audit?action=login_success,login_failed&limit=10").then(r => r.json()).catch(() => ({ logs: [] })),
    ]).then(([profileData, auditData]) => {
      setInfo({
        lastLogin:    profileData.user?.lastLogin ?? null,
        loginHistory: (auditData.logs ?? []).map((l: { createdAt: string; actorIp: string | null; result: string }) => ({
          createdAt: l.createdAt,
          actorIp:   l.actorIp,
          result:    l.result,
        })),
      });
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="px-6 py-8 text-sm text-zinc-500">Loading…</div>;

  return (
    <div className="mx-auto max-w-2xl px-6 py-8 space-y-8">
      <div className="flex items-center gap-3">
        <ShieldCheck className="h-5 w-5 text-teal-400" />
        <h1 className="text-xl font-bold text-zinc-100">Security</h1>
      </div>

      {/* Security overview */}
      <div className="grid grid-cols-1 gap-4">
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-1">
          <div className="flex items-center gap-2 text-zinc-400 text-xs font-medium">
            <Clock className="h-3.5 w-3.5" /> Last Login
          </div>
          <p className="text-sm font-medium text-zinc-200">
            {info?.lastLogin ? new Date(info.lastLogin).toLocaleString() : "—"}
          </p>
        </div>
      </div>

      {/* Password */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <CheckCircle2 className="h-5 w-5 text-teal-400" />
          <div>
            <p className="text-sm font-semibold text-zinc-200">Password</p>
            <p className="text-xs text-zinc-500">Change your password in your profile settings.</p>
          </div>
        </div>
        <Link href="/settings/profile" className="rounded-md border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800">
          Change
        </Link>
      </div>

      {/* MFA placeholder */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 flex items-center justify-between opacity-60">
        <div className="flex items-center gap-3">
          <ShieldCheck className="h-5 w-5 text-zinc-500" />
          <div>
            <p className="text-sm font-semibold text-zinc-400">Two-Factor Authentication</p>
            <p className="text-xs text-zinc-600">TOTP (Google/Microsoft Authenticator) — coming soon.</p>
          </div>
        </div>
        <span className="rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-500">Soon</span>
      </div>

      {/* Recent login history */}
      {info && info.loginHistory.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-zinc-300">Recent Login Activity</h2>
          <div className="rounded-lg border border-zinc-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-zinc-900 text-xs text-zinc-500 uppercase">
                <tr>
                  <th className="px-4 py-2 text-left">Time</th>
                  <th className="px-4 py-2 text-left">IP</th>
                  <th className="px-4 py-2 text-left">Result</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800 bg-zinc-950">
                {info.loginHistory.map((log, i) => (
                  <tr key={i}>
                    <td className="px-4 py-2 text-zinc-400">{new Date(log.createdAt).toLocaleString()}</td>
                    <td className="px-4 py-2 font-mono text-zinc-500 text-xs">{log.actorIp ?? "—"}</td>
                    <td className="px-4 py-2">
                      <span className={`flex items-center gap-1 text-xs ${log.result === "success" ? "text-teal-400" : "text-red-400"}`}>
                        {log.result === "success"
                          ? <CheckCircle2 className="h-3 w-3" />
                          : <AlertCircle className="h-3 w-3" />}
                        {log.result}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
