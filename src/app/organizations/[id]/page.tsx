"use client";
import { useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import {
  Building2, Pencil, Save, Loader2, Upload, Trash2,
  Users, X, Plus, AlertCircle, CheckCircle2, Globe, Info,
} from "lucide-react";

interface Member { id: string; role: string; user: { id: string; email: string; name?: string | null } }
interface Org {
  id: string; name: string; slug: string; plan: string;
  description?: string | null; logoUrl?: string | null; website?: string | null;
  settings: Record<string, unknown>;
  members: Member[];
  _count: { investigations: number; cases: number; hostProfiles: number };
}

const PLAN_LABELS: Record<string, string> = { free: "Free", enterprise: "Enterprise" };
const PLAN_COLOR: Record<string, string> = {
  free: "bg-zinc-800 text-zinc-400",
  enterprise: "bg-orange-900/40 text-orange-300",
};

export default function OrgDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { data: session } = useSession();
  const role = session?.user?.role ?? "";
  const isPlatformAdmin = role === "platform_admin";
  const isAppliance = process.env.NEXT_PUBLIC_DEPLOYMENT_MODE === "appliance";

  const [org, setOrg] = useState<Org | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");
  // See organizations/page.tsx for why: appliance mode's single org IS the
  // license holder, so its own independent `plan` field is meaningless
  // there — show the real activated license's plan instead.
  const [licensePlan, setLicensePlan] = useState<string | null>(null);

  // Edit fields
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [website, setWebsite] = useState("");
  const [plan, setPlan] = useState("free");
  const [logoPreview, setLogoPreview] = useState<string | null>(null);
  const [logoFile, setLogoFile] = useState<File | null>(null);
  const logoRef = useRef<HTMLInputElement>(null);

  // Member mgmt
  const [addEmail, setAddEmail] = useState("");
  const [addMemberRole, setAddMemberRole] = useState("analyst");
  const [addingMember, setAddingMember] = useState(false);
  const [memberError, setMemberError] = useState("");

  async function load() {
    setLoading(true);
    const requests: Promise<unknown>[] = [fetch(`/api/organizations/${id}`)];
    if (isAppliance) requests.push(fetch("/api/license/status").then(r => r.json()).catch(() => null));
    const [r, licenseData] = await Promise.all(requests) as [Response, { plan?: string } | null];
    if (!r.ok) { setLoading(false); return; }
    const d = await r.json();
    const o: Org = d.organization;
    setOrg(o);
    setName(o.name);
    setDescription(o.description ?? "");
    setWebsite(o.website ?? "");
    setPlan(o.plan);
    setLogoPreview(o.logoUrl ?? null);
    if (isAppliance) setLicensePlan(licenseData?.plan ?? null);
    setLoading(false);
  }

  useEffect(() => { load(); }, [id]);

  function pickLogo(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setLogoFile(file);
    setLogoPreview(URL.createObjectURL(file));
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setError(""); setSuccess(""); setSaving(true);

    let uploadedLogoUrl: string | undefined;
    if (logoFile) {
      const fd = new FormData();
      fd.append("file", logoFile);
      fd.append("organizationId", id);
      const up = await fetch("/api/upload/logo", { method: "POST", body: fd });
      if (up.ok) { const d = await up.json(); uploadedLogoUrl = d.url; }
      else { setError("Logo upload failed. You can still save other fields."); }
    }

    const body: Record<string, unknown> = { name, description: description || null, website: website || null };
    if (isPlatformAdmin) body.plan = plan;
    if (uploadedLogoUrl) body.logoUrl = uploadedLogoUrl;

    const res = await fetch(`/api/organizations/${id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const d = await res.json();
    if (res.ok) { setSuccess("Organization updated successfully."); setOrg(d.organization); setLogoFile(null); }
    else setError(d.error ?? "Update failed.");
    setSaving(false);
  }

  async function addMember(e: React.FormEvent) {
    e.preventDefault();
    setMemberError(""); setAddingMember(true);
    const res = await fetch(`/api/organizations/${id}/members`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: addEmail, role: addMemberRole }),
    });
    const d = await res.json();
    if (res.ok) { setAddEmail(""); load(); }
    else setMemberError(d.error ?? "Failed to add member.");
    setAddingMember(false);
  }

  async function removeMember(userId: string) {
    if (!confirm("Remove this member from the organization?")) return;
    await fetch(`/api/organizations/${id}/members`, {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ userId }),
    });
    load();
  }

  async function deleteOrg() {
    if (!isPlatformAdmin) return;
    if (!confirm("Permanently delete this organization and ALL its data? This cannot be undone.")) return;
    await fetch(`/api/organizations/${id}`, { method: "DELETE" });
    router.push("/organizations");
  }

  if (loading) return <div className="mx-auto max-w-4xl px-6 py-8 text-sm text-zinc-500">Loading…</div>;
  if (!org) return <div className="mx-auto max-w-4xl px-6 py-8 text-sm text-red-400">Organization not found.</div>;

  return (
    <div className="mx-auto max-w-4xl px-6 py-8 space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          {logoPreview ? (
            <img src={logoPreview} alt="" className="h-14 w-14 rounded-lg object-contain bg-zinc-800 border border-zinc-700" />
          ) : (
            <div className="flex h-14 w-14 items-center justify-center rounded-lg bg-zinc-800 border border-zinc-700">
              <Building2 className="h-7 w-7 text-zinc-600" />
            </div>
          )}
          <div>
            <h1 className="text-xl font-semibold text-zinc-100">{org.name}</h1>
            <p className="text-sm text-zinc-500">{org.slug}</p>
            <span className={`mt-1 inline-block rounded-full px-2 py-0.5 text-xs font-medium ${PLAN_COLOR[isAppliance ? (licensePlan ?? "") : org.plan] ?? "bg-zinc-800 text-zinc-400"}`}>
              {isAppliance ? (licensePlan ? (PLAN_LABELS[licensePlan] ?? licensePlan) : "Unlicensed") : (PLAN_LABELS[org.plan] ?? org.plan)}
            </span>
          </div>
        </div>
        {isPlatformAdmin && (
          <button onClick={deleteOrg} className="flex items-center gap-1.5 rounded-md border border-red-900 px-3 py-1.5 text-xs text-red-400 hover:bg-red-950">
            <Trash2 className="h-3.5 w-3.5" /> Delete Org
          </button>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Investigations", value: org._count.investigations },
          { label: "Cases",          value: org._count.cases },
          { label: "Members",        value: org.members.length },
        ].map(s => (
          <div key={s.label} className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 text-center">
            <p className="text-2xl font-bold text-zinc-100">{s.value}</p>
            <p className="text-xs text-zinc-500 mt-1">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Edit form */}
      <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-6 space-y-5">
        <h2 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
          <Pencil className="h-4 w-4 text-zinc-500" /> Organization Settings
        </h2>

        {success && (
          <div className="flex items-center gap-2 rounded-lg border border-teal-900 bg-teal-950/40 px-3 py-2 text-sm text-teal-400">
            <CheckCircle2 className="h-4 w-4 shrink-0" />{success}
          </div>
        )}
        {error && (
          <div className="flex items-center gap-2 rounded-lg border border-red-900 bg-red-950/50 px-3 py-2 text-sm text-red-400">
            <AlertCircle className="h-4 w-4 shrink-0" />{error}
          </div>
        )}

        <form onSubmit={save} className="space-y-4">
          {/* Logo */}
          <div className="space-y-2">
            <label className="text-xs font-medium text-zinc-400">Organization Logo
              <span className="ml-1 text-zinc-600">(used on generated reports)</span>
            </label>
            <div className="flex items-center gap-4">
              {logoPreview ? (
                <div className="relative">
                  <img src={logoPreview} alt="" className="h-16 w-16 rounded-lg object-contain bg-zinc-800 border border-zinc-700" />
                  <button type="button" onClick={() => { setLogoPreview(org?.logoUrl ?? null); setLogoFile(null); if (logoRef.current) logoRef.current.value = ""; }}
                    className="absolute -top-1.5 -right-1.5 rounded-full bg-zinc-700 p-0.5 text-zinc-400 hover:text-red-400">
                    <X className="h-3 w-3" />
                  </button>
                </div>
              ) : (
                <div className="flex h-16 w-16 items-center justify-center rounded-lg border border-dashed border-zinc-700 bg-zinc-800">
                  <Building2 className="h-6 w-6 text-zinc-600" />
                </div>
              )}
              <div>
                <button type="button" onClick={() => logoRef.current?.click()}
                  className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-xs text-zinc-400 hover:bg-zinc-800">
                  <Upload className="h-3.5 w-3.5" /> {logoPreview ? "Change Logo" : "Upload Logo"}
                </button>
                <p className="mt-1 text-xs text-zinc-600">PNG, JPG or SVG · max 2 MB</p>
                <input ref={logoRef} type="file" accept="image/png,image/jpeg,image/svg+xml,image/webp" className="hidden" onChange={pickLogo} />
              </div>
            </div>
          </div>

          {/* Name */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-zinc-400">Organization Name *</label>
            <input required value={name} onChange={e => setName(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none" />
          </div>

          {/* Description */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-zinc-400">Description</label>
            <textarea value={description} onChange={e => setDescription(e.target.value)} rows={2}
              placeholder="Short description of this organization…"
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none resize-none" />
          </div>

          {/* Website */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-zinc-400 flex items-center gap-1">
              <Globe className="h-3 w-3" /> Website
            </label>
            <input type="url" value={website} onChange={e => setWebsite(e.target.value)}
              placeholder="https://example.com"
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none" />
          </div>

          {/* Plan — platform_admin only */}
          {isPlatformAdmin && (
            <div className="space-y-1">
              <label className="text-xs font-medium text-zinc-400">Plan</label>
              <select value={plan} onChange={e => setPlan(e.target.value)}
                className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none">
                <option value="free">Free</option>
                <option value="enterprise">Enterprise</option>
              </select>
            </div>
          )}

          {!isPlatformAdmin && (
            <div className="flex items-start gap-2 rounded-md border border-zinc-800 bg-zinc-950/40 px-3 py-2 text-xs text-zinc-500">
              <Info className="h-3.5 w-3.5 mt-0.5 shrink-0" />
              Slug and plan changes require platform administrator access.
            </div>
          )}

          <div className="flex justify-end">
            <button type="submit" disabled={saving}
              className="flex items-center gap-2 rounded-md bg-teal-700 px-4 py-2 text-sm font-medium text-white hover:bg-teal-600 disabled:opacity-50">
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              {saving ? "Saving…" : "Save Changes"}
            </button>
          </div>
        </form>
      </section>

      {/* Members */}
      <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-6 space-y-4">
        <h2 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
          <Users className="h-4 w-4 text-zinc-500" /> Members ({org.members.length})
        </h2>

        {memberError && (
          <div className="flex items-center gap-2 rounded-lg border border-red-900 bg-red-950/50 px-3 py-2 text-sm text-red-400">
            <AlertCircle className="h-4 w-4 shrink-0" />{memberError}
          </div>
        )}

        <form onSubmit={addMember} className="flex flex-wrap gap-2">
          <input required type="email" value={addEmail} onChange={e => setAddEmail(e.target.value)}
            placeholder="user@example.com"
            className="flex-1 min-w-48 rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500" />
          <select value={addMemberRole} onChange={e => setAddMemberRole(e.target.value)}
            className="rounded border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 outline-none focus:border-teal-500">
            <option value="org_admin">Org Admin</option>
            <option value="analyst">Analyst</option>
            <option value="read_only">Read Only</option>
            <option value="auditor">Auditor</option>
          </select>
          <button type="submit" disabled={addingMember}
            className="flex items-center gap-1 rounded bg-teal-600 px-3 py-1.5 text-sm text-white hover:bg-teal-500 disabled:opacity-50">
            <Plus className="h-3.5 w-3.5" />{addingMember ? "Adding…" : "Add Member"}
          </button>
        </form>

        <div className="divide-y divide-zinc-800">
          {org.members.map(m => (
            <div key={m.id} className="flex items-center justify-between py-2.5">
              <div>
                <p className="text-sm text-zinc-200">{m.user.name ?? m.user.email}</p>
                {m.user.name && <p className="text-xs text-zinc-600">{m.user.email}</p>}
              </div>
              <div className="flex items-center gap-3">
                <span className="rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">{m.role}</span>
                <button onClick={() => removeMember(m.user.id)} className="text-zinc-600 hover:text-red-400" title="Remove member">
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

