"use client";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { Building2, Plus, Trash2, Users, Pencil } from "lucide-react";
import Link from "next/link";

interface Org { id: string; name: string; slug: string; plan: string; description?: string; logoUrl?: string; createdAt: string; _count?: { members: number; investigations: number } }

export default function OrganizationsPage() {
  const { data: session } = useSession();
  const role = session?.user?.role ?? "";
  const isAppliance = process.env.NEXT_PUBLIC_DEPLOYMENT_MODE === "appliance";
  const isPlatformAdmin = role === "platform_admin" && !isAppliance;

  const [orgs, setOrgs] = useState<Org[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");
  // Appliance mode has exactly one org, and it IS the license holder — the
  // org's own independent `plan` field (a free-standing label a
  // platform_admin can set, unused for any actual enforcement, and a role
  // that doesn't even exist in appliance mode) is meaningless noise there.
  // Show the real activated license's plan instead. SaaS orgs keep their
  // own plan as-is — legitimate independent per-tenant billing tiers,
  // unrelated to whatever license the platform operator holds.
  const [licensePlan, setLicensePlan] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    const requests: Promise<unknown>[] = [fetch("/api/organizations").then(r => r.json())];
    if (isAppliance) requests.push(fetch("/api/license/status").then(r => r.json()).catch(() => null));
    const [orgsData, licenseData] = await Promise.all(requests);
    setOrgs((orgsData as { organizations?: Org[] }).organizations ?? []);
    if (isAppliance) setLicensePlan((licenseData as { plan?: string } | null)?.plan ?? null);
    setLoading(false);
  }

  useEffect(() => { load(); }, []);

  async function createOrg(e: React.FormEvent) {
    e.preventDefault();
    setCreateError("");
    setCreating(true);
    const res = await fetch("/api/organizations", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name, slug }) });
    const d = await res.json();
    if (res.ok) { setShowCreate(false); setName(""); setSlug(""); load(); }
    else setCreateError(d.error ?? "Failed to create.");
    setCreating(false);
  }

  async function deleteOrg(id: string) {
    if (!confirm("Permanently delete this organization and all its data? This cannot be undone.")) return;
    await fetch(`/api/organizations/${id}`, { method: "DELETE" });
    load();
  }

  return (
    <div className="mx-auto max-w-6xl px-6 py-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">Organizations</h1>
          <p className="text-sm text-zinc-500">
            {isPlatformAdmin ? "Manage all tenant organizations" : "Your organization settings"}
          </p>
        </div>
        {isPlatformAdmin && (
          <button onClick={() => setShowCreate(true)} className="flex items-center gap-1.5 rounded-md bg-teal-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-500">
            <Plus className="h-4 w-4" /> New Organization
          </button>
        )}
      </div>

      {showCreate && isPlatformAdmin && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3">
          <h2 className="text-sm font-semibold text-zinc-200">Create Organization</h2>
          {createError && <p className="text-sm text-red-400">{createError}</p>}
          <form onSubmit={createOrg} className="flex flex-wrap gap-3">
            <input required value={name} onChange={e => setName(e.target.value)} placeholder="Name" className="rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500" />
            <input required value={slug} onChange={e => setSlug(e.target.value.toLowerCase().replace(/\s+/g, "-"))} placeholder="Slug (e.g. acme-corp)" className="rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500" />
            <button type="submit" disabled={creating} className="rounded bg-teal-600 px-3 py-1.5 text-sm text-white hover:bg-teal-500 disabled:opacity-50">{creating ? "Creating…" : "Create"}</button>
            <button type="button" onClick={() => { setShowCreate(false); setCreateError(""); }} className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:text-zinc-200">Cancel</button>
          </form>
        </div>
      )}

      {loading ? (
        <p className="text-sm text-zinc-500">Loading…</p>
      ) : orgs.length === 0 ? (
        <div className="rounded-lg border border-dashed border-zinc-800 p-12 text-center text-zinc-600">
          <Building2 className="mx-auto mb-2 h-8 w-8" />
          No organizations yet
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {orgs.map(org => (
            <div key={org.id} className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  {org.logoUrl && <img src={org.logoUrl} alt="" className="h-8 w-8 rounded object-contain bg-zinc-800" />}
                  <div>
                    <Link href={`/organizations/${org.id}`} className="font-semibold text-zinc-100 hover:text-teal-400">{org.name}</Link>
                    <p className="text-xs text-zinc-600">{org.slug}</p>
                  </div>
                </div>
                <span className="rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">
                  {isAppliance ? (licensePlan ?? "Unlicensed") : org.plan}
                </span>
              </div>
              <div className="flex items-center gap-1 text-xs text-zinc-500">
                <Users className="h-3.5 w-3.5" />
                {org._count?.members ?? 0} members
              </div>
              <div className="flex items-center gap-2">
                <Link href={`/organizations/${org.id}`} className="flex items-center gap-1 text-xs text-teal-500 hover:text-teal-400">
                  <Pencil className="h-3 w-3" /> {isPlatformAdmin ? "Manage" : "Edit"}
                </Link>
                {isPlatformAdmin && (
                  <button onClick={() => deleteOrg(org.id)} className="ml-auto text-zinc-600 hover:text-red-400" title="Delete organization">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
