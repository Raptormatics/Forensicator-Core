"use client";
/**
 * Intelligence → Sigma → Rule Library: Core's SigmaHQ rules (downloaded in
 * Settings → Threat Intelligence), with their hit counts, why a rule doesn't
 * run, and an on/off switch for admins.
 */
import { useEffect, useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import { severityClassName, normalizeSeverity } from "@/lib/severity";

type RuleRow = {
  id: string; sigmaId: string; title: string; level: string; status: string | null;
  product: string | null; category: string | null; service: string | null; tags: string[];
  enabled: boolean; supported: boolean; covered: boolean; unsupportedReason: string | null; hitCount: number;
};
type RuleDetail = RuleRow & { description: string | null; author: string | null; references: string[]; falsePositives: string[]; yaml: string; path: string | null };

const STATES = [
  { id: "", label: "All rules" },
  { id: "active", label: "Active" },
  { id: "disabled", label: "Turned off" },
  { id: "no_source", label: "No log source in Core" },
  { id: "unsupported", label: "Not supported" },
];

function logsource(r: { product: string | null; category: string | null; service: string | null }) {
  return [r.product, r.category, r.service].filter(Boolean).join(" / ") || "—";
}

export function SigmaRuleLibrary({ canManage }: { canManage?: boolean }) {
  const { data: session } = useSession();
  const [rules, setRules] = useState<RuleRow[]>([]);
  const [total, setTotal] = useState(0);
  const [products, setProducts] = useState<{ product: string; count: number }[]>([]);
  const [q, setQ] = useState("");
  const [level, setLevel] = useState("");
  const [state, setState] = useState("");
  const [product, setProduct] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<RuleDetail | null>(null);
  const PAGE = 100;
  // The server enforces instance-admin for the toggle; this only hides it.
  const manage = canManage ?? !!session?.user;

  async function load(next = { q, level, state, product, offset }) {
    setLoading(true);
    const p = new URLSearchParams({ limit: String(PAGE), offset: String(next.offset) });
    if (next.q) p.set("q", next.q);
    if (next.level) p.set("level", next.level);
    if (next.state) p.set("state", next.state);
    if (next.product) p.set("product", next.product);
    const r = await fetch(`/api/sigma/rules?${p}`);
    if (r.ok) {
      const d = await r.json();
      setRules(d.rules); setTotal(d.total); setProducts(d.products);
    }
    setLoading(false);
  }
  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function apply(patch: Partial<{ q: string; level: string; state: string; product: string; offset: number }>) {
    const next = { q, level, state, product, offset: 0, ...patch };
    setQ(next.q); setLevel(next.level); setState(next.state); setProduct(next.product); setOffset(next.offset);
    load(next);
  }

  async function toggle(r: RuleRow) {
    const res = await fetch(`/api/sigma/rules/${r.id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: !r.enabled }) });
    if (res.ok) setRules((rs) => rs.map((x) => (x.id === r.id ? { ...x, enabled: !r.enabled } : x)));
  }

  async function show(r: RuleRow) {
    const res = await fetch(`/api/sigma/rules/${r.id}`);
    if (res.ok) setOpen((await res.json()).rule);
  }

  return (
    <div>
      <div className="mb-4 flex flex-wrap gap-3">
        <form onSubmit={(e) => { e.preventDefault(); apply({ q }); }} className="flex gap-2">
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, tag (attack.t1059), id…"
            className="w-72 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500" />
          <button type="submit" className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 hover:border-zinc-500">Search</button>
        </form>
        <select value={state} onChange={(e) => apply({ state: e.target.value })} className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300">
          {STATES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
        </select>
        <select value={level} onChange={(e) => apply({ level: e.target.value })} className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300">
          <option value="">All levels</option>
          {["critical", "high", "medium", "low", "informational"].map((l) => <option key={l} value={l}>{l}</option>)}
        </select>
        <select value={product} onChange={(e) => apply({ product: e.target.value })} className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300">
          <option value="">All products</option>
          {products.map((p) => <option key={p.product} value={p.product}>{p.product} ({p.count})</option>)}
        </select>
        <span className="self-center text-xs text-zinc-600">{total.toLocaleString()} rule{total === 1 ? "" : "s"}</span>
      </div>

      {loading ? (
        <div className="py-16 text-center text-zinc-600">Loading rules…</div>
      ) : rules.length === 0 ? (
        <div className="py-16 text-center text-zinc-600">
          <p>No Sigma rules{q || level || state || product ? " match these filters" : " yet"}.</p>
          {!(q || level || state || product) && (
            <p className="mt-1 text-xs text-zinc-700">
              Download the SigmaHQ rules in <Link href="/settings/threat-intel" className="text-teal-400 hover:text-teal-300">Settings → Threat Intelligence</Link>.
            </p>
          )}
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-zinc-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/80 text-left text-zinc-400">
                <th className="px-4 py-3 font-medium">Rule</th>
                <th className="px-4 py-3 font-medium">Level</th>
                <th className="px-4 py-3 font-medium">Log source</th>
                <th className="px-4 py-3 font-medium">State</th>
                <th className="px-4 py-3 font-medium text-right">Hits</th>
                {manage && <th className="px-4 py-3 font-medium">On</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {rules.map((r) => (
                <tr key={r.id} className="bg-zinc-950 hover:bg-zinc-900/70">
                  <td className="max-w-md px-4 py-2.5">
                    <button onClick={() => show(r)} className="text-left font-medium text-zinc-100 hover:text-teal-300">{r.title}</button>
                    {r.tags.length > 0 && <div className="mt-0.5 truncate text-[11px] text-zinc-600">{r.tags.join(" · ")}</div>}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`inline-flex rounded border px-2 py-0.5 text-[11px] font-semibold uppercase ${severityClassName(r.level)}`}>{normalizeSeverity(r.level)}</span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-zinc-500">{logsource(r)}</td>
                  <td className="px-4 py-2.5 text-xs">
                    {!r.supported ? <span className="text-zinc-500" title={r.unsupportedReason ?? ""}>Not supported</span>
                      : !r.covered ? <span className="text-zinc-500">No log source in Core</span>
                      : r.enabled ? <span className="text-teal-400">Active</span>
                      : <span className="text-zinc-500">Turned off</span>}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono text-xs text-zinc-400">{r.hitCount.toLocaleString()}</td>
                  {manage && (
                    <td className="px-4 py-2.5">
                      <input type="checkbox" checked={r.enabled} onChange={() => toggle(r)} aria-label={`Turn ${r.title} ${r.enabled ? "off" : "on"}`} />
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {total > PAGE && (
        <div className="mt-3 flex items-center justify-end gap-2 text-xs text-zinc-500">
          <button disabled={offset === 0} onClick={() => { const o = Math.max(0, offset - PAGE); setOffset(o); load({ q, level, state, product, offset: o }); }}
            className="rounded border border-zinc-800 px-2 py-1 disabled:opacity-40">Previous</button>
          <span>{offset + 1}–{Math.min(offset + PAGE, total)} of {total.toLocaleString()}</span>
          <button disabled={offset + PAGE >= total} onClick={() => { const o = offset + PAGE; setOffset(o); load({ q, level, state, product, offset: o }); }}
            className="rounded border border-zinc-800 px-2 py-1 disabled:opacity-40">Next</button>
        </div>
      )}

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setOpen(null)}>
          <div className="max-h-[85vh] w-full max-w-3xl overflow-auto rounded-xl border border-zinc-800 bg-zinc-950 p-5" onClick={(e) => e.stopPropagation()}>
            <div className="mb-2 flex items-start justify-between gap-3">
              <h3 className="text-lg font-semibold text-zinc-100">{open.title}</h3>
              <button onClick={() => setOpen(null)} className="text-sm text-zinc-500 hover:text-zinc-200">Close</button>
            </div>
            {open.description && <p className="mb-3 text-sm text-zinc-400">{open.description}</p>}
            <dl className="mb-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
              <dt className="text-zinc-600">Sigma id</dt><dd className="font-mono text-zinc-300">{open.sigmaId}</dd>
              <dt className="text-zinc-600">Level / status</dt><dd className="text-zinc-300">{open.level} / {open.status ?? "—"}</dd>
              <dt className="text-zinc-600">Log source</dt><dd className="font-mono text-zinc-300">{logsource(open)}</dd>
              {open.author && (<><dt className="text-zinc-600">Author</dt><dd className="text-zinc-300">{open.author}</dd></>)}
              {!open.supported && (<><dt className="text-zinc-600">Why it doesn&apos;t run</dt><dd className="text-zinc-300">{open.unsupportedReason}</dd></>)}
            </dl>
            {open.falsePositives.length > 0 && (
              <div className="mb-3 text-xs"><span className="text-zinc-600">False positives: </span><span className="text-zinc-400">{open.falsePositives.join("; ")}</span></div>
            )}
            {open.references.length > 0 && (
              <ul className="mb-3 space-y-0.5 text-xs">
                {open.references.map((ref) => <li key={ref}><a href={ref} target="_blank" rel="noreferrer" className="break-all text-teal-400 hover:text-teal-300">{ref}</a></li>)}
              </ul>
            )}
            <pre className="overflow-auto rounded-md bg-zinc-900 p-3 text-[11px] leading-relaxed text-zinc-300">{open.yaml}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
