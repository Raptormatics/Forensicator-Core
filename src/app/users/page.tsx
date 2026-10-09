"use client";

import { useEffect, useState, useCallback } from "react";
import { useSession } from "next-auth/react";
import {
  Users, Plus, Search, Shield, ShieldOff, Pencil,
  X, Save, Loader2, CheckCircle2, AlertCircle, UserPlus, Trash2,
} from "lucide-react";

interface User {
  id: string;
  email: string;
  name?: string | null;
  role: string;
  isActive: boolean;
  lastLogin?: string | null;
  createdAt: string;
  orgMemberships: { role: string; organization: { id: string; name: string } }[];
  _count: { investigations: number; createdCases: number };
}

const ROLE_LABELS: Record<string, string> = {
  platform_admin: "Platform Admin",
  org_admin:      "Org Admin",
  analyst:        "Analyst",
  read_only:      "Read Only",
  auditor:        "Auditor",
};

const ROLE_COLOR: Record<string, string> = {
  platform_admin: "bg-red-900/40 text-red-300 border border-red-800",
  org_admin:      "bg-orange-900/40 text-orange-300 border border-orange-800",
  analyst:        "bg-teal-900/40 text-teal-300 border border-teal-800",
  read_only:      "bg-zinc-800 text-zinc-400 border border-zinc-700",
  auditor:        "bg-purple-900/40 text-purple-300 border border-purple-800",
};

// ── Create User Modal ─────────────────────────────────────────────────────────
function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const { data: session } = useSession();
  const actorRole  = session?.user?.role ?? "";
  const isOrgAdmin = actorRole === "org_admin";

  const [email,    setEmail]    = useState("");
  const [name,     setName]     = useState("");
  const [password, setPassword] = useState("");
  const [role,     setRole]     = useState("analyst");
  const [orgId,    setOrgId]    = useState("");
  const [orgs,     setOrgs]     = useState<{ id: string; name: string }[]>([]);
  const [saving,   setSaving]   = useState(false);
  const [error,    setError]    = useState("");

  // org_admin must always have an org; analyst/read_only too
  const ORG_REQUIRED = ["org_admin", "analyst", "read_only"];

  // Roles an org_admin is allowed to create
  const ALLOWED_ROLES = isOrgAdmin
    ? Object.entries(ROLE_LABELS).filter(([v]) => v !== "platform_admin")
    : Object.entries(ROLE_LABELS);

  useEffect(() => {
    fetch("/api/organizations")
      .then(r => r.json())
      .then(d => {
        const list: { id: string; name: string }[] = d.organizations ?? [];
        setOrgs(list);
        // For org_admin, pre-select their org and lock it
        if (isOrgAdmin && list.length > 0) setOrgId(list[0].id);
      })
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (ORG_REQUIRED.includes(role) && !orgId) {
      setError(`An organization must be selected for the '${role}' role.`);
      return;
    }
    setError("");
    setSaving(true);
    const res = await fetch("/api/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: email.trim().toLowerCase(),
        name: name.trim() || undefined,
        password,
        role,
        organizationId: orgId || undefined,
      }),
    });
    const d = await res.json();
    if (res.ok) { onCreated(); onClose(); }
    else setError(d.error ?? "Failed to create user.");
    setSaving(false);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-md rounded-xl border border-zinc-700 bg-zinc-900 shadow-2xl">
        <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
          <div className="flex items-center gap-2">
            <UserPlus className="h-4 w-4 text-teal-400" />
            <h2 className="text-sm font-semibold text-zinc-100">Create User</h2>
          </div>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300"><X className="h-4 w-4" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {error && (
            <div className="flex items-center gap-2 rounded-lg border border-red-900 bg-red-950/50 px-3 py-2 text-sm text-red-400">
              <AlertCircle className="h-4 w-4 shrink-0" />{error}
            </div>
          )}
          <div className="space-y-1">
            <label className="text-xs font-medium text-zinc-400">Email address *</label>
            <input required type="email" value={email} onChange={e => setEmail(e.target.value)}
              placeholder="analyst@example.com"
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none" />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-zinc-400">Display name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="Jane Smith"
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none" />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-zinc-400">Role *</label>
            <select value={role} onChange={e => { setRole(e.target.value); if (!ORG_REQUIRED.includes(e.target.value) && !isOrgAdmin) setOrgId(""); }}
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none">
              {ALLOWED_ROLES.map(([v, l]) => (
                <option key={v} value={v}>{l}</option>
              ))}
            </select>
          </div>
          {/* Organization — required for org_admin / analyst / read_only; locked for org_admin actors */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-zinc-400">
              Organization {ORG_REQUIRED.includes(role) ? <span className="text-red-400">*</span> : <span className="text-zinc-600">(optional)</span>}
            </label>
            {isOrgAdmin ? (
              <div className="w-full rounded-md border border-zinc-700 bg-zinc-800/50 px-3 py-2 text-sm text-zinc-400 cursor-not-allowed">
                {orgs.find(o => o.id === orgId)?.name ?? "Your organization"}
                <span className="ml-2 text-xs text-zinc-600">(auto-assigned)</span>
              </div>
            ) : (
              <select
                value={orgId}
                onChange={e => setOrgId(e.target.value)}
                required={ORG_REQUIRED.includes(role)}
                className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none"
              >
                <option value="">— Select organization —</option>
                {orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
              </select>
            )}
            {ORG_REQUIRED.includes(role) && !isOrgAdmin && (
              <p className="text-xs text-amber-500">Required for the &apos;{ROLE_LABELS[role]}&apos; role.</p>
            )}
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-zinc-400">Initial password * (min 8 chars)</label>
            <input required type="password" minLength={8} value={password} onChange={e => setPassword(e.target.value)}
              placeholder="Temporary password"
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none" />
          </div>
          <p className="text-xs text-zinc-600">The user should change their password on first login.</p>
          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={onClose} className="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-400 hover:bg-zinc-800">Cancel</button>
            <button type="submit" disabled={saving}
              className="flex items-center gap-2 rounded-md bg-teal-700 px-4 py-2 text-sm font-medium text-white hover:bg-teal-600 disabled:opacity-50">
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <UserPlus className="h-4 w-4" />}
              {saving ? "Creating…" : "Create User"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Edit Role Modal ───────────────────────────────────────────────────────────
function EditRoleModal({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: () => void }) {
  const [role,   setRole]   = useState(user.role);
  const [saving, setSaving] = useState(false);
  const [error,  setError]  = useState("");

  async function save() {
    setError(""); setSaving(true);
    const res = await fetch(`/api/users/${user.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role }),
    });
    const d = await res.json();
    if (res.ok) { onSaved(); onClose(); }
    else setError(d.error ?? "Failed.");
    setSaving(false);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-sm rounded-xl border border-zinc-700 bg-zinc-900 shadow-2xl">
        <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-zinc-100">Edit Role — {user.name ?? user.email}</h2>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300"><X className="h-4 w-4" /></button>
        </div>
        <div className="p-5 space-y-4">
          {error && <p className="text-sm text-red-400">{error}</p>}
          <select value={role} onChange={e => setRole(e.target.value)}
            className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none">
            {Object.entries(ROLE_LABELS).map(([v, l]) => (
              <option key={v} value={v}>{l}</option>
            ))}
          </select>
          <div className="flex justify-end gap-2">
            <button onClick={onClose} className="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-400 hover:bg-zinc-800">Cancel</button>
            <button onClick={save} disabled={saving || role === user.role}
              className="flex items-center gap-2 rounded-md bg-teal-700 px-4 py-2 text-sm font-medium text-white hover:bg-teal-600 disabled:opacity-50">
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              Save
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function UsersPage() {
  const { data: session } = useSession();
  const isAdmin        = ["platform_admin", "org_admin"].includes(session?.user?.role ?? "");
  const isPlatformAdmin = session?.user?.role === "platform_admin";
  const isOrgAdmin      = session?.user?.role === "org_admin";

  const [users,   setUsers]   = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [q,       setQ]       = useState("");
  const [total,   setTotal]   = useState(0);
  const [page,    setPage]    = useState(1);
  const [pages,   setPages]   = useState(1);

  const [showCreate, setShowCreate] = useState(false);
  const [editUser,   setEditUser]   = useState<User | null>(null);
  const [toast,      setToast]      = useState<{ ok: boolean; text: string } | null>(null);

  const showToast = (ok: boolean, text: string) => {
    setToast({ ok, text });
    setTimeout(() => setToast(null), 3500);
  };

  const load = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({ page: String(page), limit: "50" });
    if (q) params.set("q", q);
    const r = await fetch(`/api/users?${params}`);
    const d = await r.json();
    setUsers(d.users ?? []);
    setTotal(d.total ?? 0);
    setPages(d.pages ?? 1);
    setLoading(false);
  }, [page, q]);

  useEffect(() => { load(); }, [load]);

  async function toggleActive(user: User) {
    const res = await fetch(`/api/users/${user.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ isActive: !user.isActive }),
    });
    if (res.ok) { showToast(true, `User ${user.isActive ? "deactivated" : "activated"}.`); load(); }
    else { const d = await res.json(); showToast(false, d.error ?? "Failed."); }
  }

  async function deleteUser(user: User) {
    if (!confirm(`Permanently delete ${user.name ?? user.email}? This action cannot be undone.`)) return;
    const res = await fetch(`/api/users/${user.id}`, { method: "DELETE" });
    const d = await res.json();
    if (res.ok) { showToast(true, "User deleted."); load(); }
    else showToast(false, d.error ?? "Delete failed.");
  }

  return (
    <div className="mx-auto max-w-7xl px-6 py-8 space-y-6">
      {/* Toast */}
      {toast && (
        <div className={`fixed bottom-4 right-4 z-50 flex items-center gap-2 rounded-lg border px-4 py-3 text-sm shadow-lg ${
          toast.ok ? "border-teal-800 bg-teal-950 text-teal-300" : "border-red-900 bg-red-950 text-red-400"
        }`}>
          {toast.ok ? <CheckCircle2 className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
          {toast.text}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Users className="h-5 w-5 text-zinc-400" />
          <div>
            <h1 className="text-xl font-bold text-zinc-100">Users</h1>
            <p className="text-sm text-zinc-500">{total.toLocaleString()} total users</p>
          </div>
        </div>
        {isAdmin && (
          <button onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 rounded-lg bg-teal-700 px-4 py-2 text-sm font-medium text-white hover:bg-teal-600">
            <Plus className="h-4 w-4" /> Create User
          </button>
        )}
      </div>

      {/* Search */}
      <div className="relative w-72">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500" />
        <input value={q} onChange={e => { setQ(e.target.value); setPage(1); }}
          placeholder="Search by name or email…"
          className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-1.5 pl-8 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none" />
      </div>

      {/* Table */}
      {loading ? <p className="text-sm text-zinc-500">Loading…</p> : users.length === 0 ? (
        <div className="rounded-lg border border-dashed border-zinc-800 p-12 text-center text-zinc-600">
          <Users className="mx-auto mb-2 h-8 w-8" /> No users found
        </div>
      ) : (
        <>
          <div className="overflow-hidden rounded-lg border border-zinc-800 text-sm">
            <table className="w-full">
              <thead className="bg-zinc-900 text-zinc-500 text-xs uppercase tracking-wide">
                <tr>
                  <th className="px-4 py-3 text-left">User</th>
                  <th className="px-4 py-3 text-left">Role</th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-left">Organizations</th>
                  <th className="px-4 py-3 text-left">Last Login</th>
                  <th className="px-4 py-3 text-left">Joined</th>
                  {isAdmin && <th className="px-4 py-3 text-right">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {users.map(u => {
                  const isSelf = u.id === session?.user?.id;
                  return (
                    <tr key={u.id} className={`bg-zinc-950 hover:bg-zinc-900/40 ${!u.isActive ? "opacity-50" : ""}`}>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-zinc-800 text-xs font-semibold text-zinc-300">
                            {(u.name ?? u.email)[0].toUpperCase()}
                          </div>
                          <div>
                            <p className="font-medium text-zinc-200">{u.name ?? u.email}</p>
                            {u.name && <p className="text-xs text-zinc-600">{u.email}</p>}
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${ROLE_COLOR[u.role] ?? "bg-zinc-800 text-zinc-400"}`}>
                          {ROLE_LABELS[u.role] ?? u.role}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`flex w-fit items-center gap-1 rounded-full px-2 py-0.5 text-xs ${
                          u.isActive ? "bg-green-900/30 text-green-400" : "bg-zinc-800 text-zinc-500"
                        }`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${u.isActive ? "bg-green-400" : "bg-zinc-600"}`} />
                          {u.isActive ? "Active" : "Inactive"}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {u.orgMemberships.map(m => (
                            <span key={m.organization.id} className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">
                              {m.organization.name}
                            </span>
                          ))}
                          {u.orgMemberships.length === 0 && <span className="text-xs text-zinc-700">—</span>}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-zinc-500">
                        {u.lastLogin ? new Date(u.lastLogin).toLocaleDateString() : "Never"}
                      </td>
                      <td className="px-4 py-3 text-xs text-zinc-600">
                        {new Date(u.createdAt).toLocaleDateString()}
                      </td>
                      {isAdmin && (
                        <td className="px-4 py-3">
                          <div className="flex items-center justify-end gap-1">
                            {!isSelf ? (
                              <>
                                <button onClick={() => setEditUser(u)} title="Edit role"
                                  className="rounded p-1.5 text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300">
                                  <Pencil className="h-3.5 w-3.5" />
                                </button>
                                {(isPlatformAdmin || (isOrgAdmin && u.role !== "platform_admin")) && (
                                  <button onClick={() => toggleActive(u)}
                                    title={u.isActive ? "Deactivate" : "Activate"}
                                    className={`rounded p-1.5 hover:bg-zinc-800 ${u.isActive ? "text-zinc-500 hover:text-red-400" : "text-zinc-600 hover:text-teal-400"}`}>
                                    {u.isActive ? <ShieldOff className="h-3.5 w-3.5" /> : <Shield className="h-3.5 w-3.5" />}
                                  </button>
                                )}
                                {(isPlatformAdmin || (isOrgAdmin && u.role !== "platform_admin")) && (
                                  <button onClick={() => deleteUser(u)}
                                    title="Delete user"
                                    className="rounded p-1.5 text-zinc-600 hover:bg-zinc-800 hover:text-red-400">
                                    <Trash2 className="h-3.5 w-3.5" />
                                  </button>
                                )}
                              </>
                            ) : (
                              <span className="text-xs text-zinc-700">You</span>
                            )}
                          </div>
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between text-xs text-zinc-600">
            <span>Page {page} of {pages} · {total} users</span>
            <div className="flex gap-2">
              <button disabled={page <= 1} onClick={() => setPage(p => p - 1)} className="rounded border border-zinc-700 px-2 py-1 hover:text-zinc-300 disabled:opacity-40">Prev</button>
              <button disabled={page >= pages} onClick={() => setPage(p => p + 1)} className="rounded border border-zinc-700 px-2 py-1 hover:text-zinc-300 disabled:opacity-40">Next</button>
            </div>
          </div>
        </>
      )}

      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onCreated={() => { showToast(true, "User created successfully."); load(); }}
        />
      )}
      {editUser && (
        <EditRoleModal
          user={editUser}
          onClose={() => setEditUser(null)}
          onSaved={() => { showToast(true, "Role updated."); load(); }}
        />
      )}
    </div>
  );
}
