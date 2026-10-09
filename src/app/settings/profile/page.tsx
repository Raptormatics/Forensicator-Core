"use client";

import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { UserCircle, Lock, Save, Loader2, CheckCircle2, AlertCircle } from "lucide-react";

interface UserProfile {
  id: string; email: string; name: string | null;
  firstName: string | null; lastName: string | null;
  role: string; lastLogin: string | null;
}

export default function ProfilePage() {
  const { data: session, update } = useSession();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  // Profile form
  const [firstName,  setFirstName]  = useState("");
  const [lastName,   setLastName]   = useState("");
  const [name,       setName]       = useState("");
  const [saving,     setSaving]     = useState(false);
  const [saveMsg,    setSaveMsg]    = useState<{ ok: boolean; text: string } | null>(null);

  // Password form
  const [currentPw, setCurrentPw] = useState("");
  const [newPw,     setNewPw]     = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [pwSaving,  setPwSaving]  = useState(false);
  const [pwMsg,     setPwMsg]     = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    fetch("/api/auth/profile")
      .then(r => r.json())
      .then(d => {
        const u = d.user;
        setProfile(u);
        setFirstName(u.firstName ?? "");
        setLastName(u.lastName ?? "");
        setName(u.name ?? "");
      })
      .finally(() => setLoading(false));
  }, []);

  async function saveProfile(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true); setSaveMsg(null);
    const res = await fetch("/api/auth/profile", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, firstName, lastName }),
    });
    const d = await res.json();
    if (res.ok) {
      setSaveMsg({ ok: true, text: "Profile updated." });
      await update({ name });
    } else {
      setSaveMsg({ ok: false, text: d.error ?? "Failed to save." });
    }
    setSaving(false);
  }

  async function changePassword(e: React.FormEvent) {
    e.preventDefault();
    setPwMsg(null);
    if (newPw !== confirmPw) { setPwMsg({ ok: false, text: "Passwords do not match." }); return; }
    if (newPw.length < 8)    { setPwMsg({ ok: false, text: "Minimum 8 characters." }); return; }
    setPwSaving(true);
    const res = await fetch("/api/auth/profile", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ currentPassword: currentPw, newPassword: newPw }),
    });
    const d = await res.json();
    if (res.ok) {
      setPwMsg({ ok: true, text: "Password changed successfully." });
      setCurrentPw(""); setNewPw(""); setConfirmPw("");
    } else {
      setPwMsg({ ok: false, text: d.error ?? "Failed to change password." });
    }
    setPwSaving(false);
  }

  if (loading) return <div className="px-6 py-8 text-sm text-zinc-500">Loading…</div>;

  return (
    <div className="mx-auto max-w-2xl px-6 py-8 space-y-8">
      <div className="flex items-center gap-3">
        <UserCircle className="h-5 w-5 text-zinc-400" />
        <h1 className="text-xl font-bold text-zinc-100">Profile</h1>
      </div>

      {/* Account info */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-2">
        <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wide">Account</p>
        <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm">
          <span className="text-zinc-500">Email</span>
          <span className="text-zinc-200">{profile?.email}</span>
          <span className="text-zinc-500">Role</span>
          <span className="text-zinc-200 capitalize">{profile?.role?.replace(/_/g, " ")}</span>
          <span className="text-zinc-500">Last login</span>
          <span className="text-zinc-200">
            {profile?.lastLogin ? new Date(profile.lastLogin).toLocaleString() : "—"}
          </span>
        </div>
      </div>

      {/* Profile form */}
      <form onSubmit={saveProfile} className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-4">
        <p className="text-sm font-semibold text-zinc-300">Edit Profile</p>
        {saveMsg && (
          <div className={`flex items-center gap-2 rounded-md px-3 py-2 text-sm ${saveMsg.ok ? "bg-teal-950/50 text-teal-400 border border-teal-800" : "bg-red-950/50 text-red-400 border border-red-900"}`}>
            {saveMsg.ok ? <CheckCircle2 className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
            {saveMsg.text}
          </div>
        )}
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-xs font-medium text-zinc-400">First name</label>
            <input value={firstName} onChange={e => setFirstName(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none" />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-zinc-400">Last name</label>
            <input value={lastName} onChange={e => setLastName(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none" />
          </div>
        </div>
        <div className="space-y-1">
          <label className="text-xs font-medium text-zinc-400">Display name</label>
          <input value={name} onChange={e => setName(e.target.value)}
            className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none" />
        </div>
        <div className="flex justify-end">
          <button type="submit" disabled={saving}
            className="flex items-center gap-2 rounded-md bg-teal-700 px-4 py-2 text-sm font-medium text-white hover:bg-teal-600 disabled:opacity-50">
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            {saving ? "Saving…" : "Save changes"}
          </button>
        </div>
      </form>

      {/* Password form */}
      <form onSubmit={changePassword} className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-4">
        <div className="flex items-center gap-2">
          <Lock className="h-4 w-4 text-zinc-500" />
          <p className="text-sm font-semibold text-zinc-300">Change Password</p>
        </div>
        {pwMsg && (
          <div className={`flex items-center gap-2 rounded-md px-3 py-2 text-sm ${pwMsg.ok ? "bg-teal-950/50 text-teal-400 border border-teal-800" : "bg-red-950/50 text-red-400 border border-red-900"}`}>
            {pwMsg.ok ? <CheckCircle2 className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
            {pwMsg.text}
          </div>
        )}
        <div className="space-y-3">
          {[
            { label: "Current password", value: currentPw, set: setCurrentPw, auto: "current-password" },
            { label: "New password",     value: newPw,     set: setNewPw,     auto: "new-password" },
            { label: "Confirm password", value: confirmPw, set: setConfirmPw, auto: "new-password" },
          ].map(({ label, value, set, auto }) => (
            <div key={label} className="space-y-1">
              <label className="text-xs font-medium text-zinc-400">{label}</label>
              <input type="password" required value={value} onChange={e => set(e.target.value)}
                autoComplete={auto} minLength={label !== "Current password" ? 8 : 1}
                className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none" />
            </div>
          ))}
        </div>
        <div className="flex justify-end">
          <button type="submit" disabled={pwSaving}
            className="flex items-center gap-2 rounded-md bg-zinc-700 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-600 disabled:opacity-50">
            {pwSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
            {pwSaving ? "Updating…" : "Update password"}
          </button>
        </div>
      </form>
    </div>
  );
}
