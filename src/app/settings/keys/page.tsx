"use client";
import { useEffect, useState } from "react";
import { Copy, Key, Plus, Trash2 } from "lucide-react";

interface ApiKey {
  id: string; name: string; keyPrefix: string; scopes: string[]; active: boolean;
  expiresAt?: string; lastUsedAt?: string; createdAt: string;
}

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [rawKey, setRawKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => { fetchKeys(); }, []);

  async function fetchKeys() {
    setLoading(true);
    try {
      const res = await fetch("/api/api-keys");
      if (res.ok) {
        const data = await res.json();
        setKeys(Array.isArray(data) ? data : (data.keys ?? data.apiKeys ?? []));
      }
    } finally { setLoading(false); }
  }

  async function createKey() {
    if (!newName.trim()) return;
    setCreating(true);
    try {
      const res = await fetch("/api/api-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newName.trim(), scopes: ["read", "write"] }),
      });
      if (res.ok) {
        const data = await res.json();
        setRawKey(data.rawKey);
        setNewName("");
        await fetchKeys();
      }
    } finally { setCreating(false); }
  }

  async function revokeKey(id: string) {
    await fetch(`/api/api-keys/${id}`, { method: "DELETE" });
    setKeys(prev => prev.filter(k => k.id !== id));
  }

  function copyKey(key: string) {
    navigator.clipboard.writeText(key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="mx-auto max-w-5xl px-6 py-8 space-y-6">
      <div className="flex items-center gap-3">
        <Key className="h-5 w-5 text-yellow-400" />
        <h1 className="text-xl font-bold text-zinc-100">API Keys</h1>
      </div>
      <p className="text-sm text-zinc-400">Create and manage API keys for programmatic access to the Forensicator API.</p>

      {rawKey && (
        <div className="rounded-lg border border-teal-800 bg-teal-950/50 p-4">
          <p className="text-sm font-semibold text-teal-400 mb-2">API Key Created — Copy it now. It won&apos;t be shown again.</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 rounded bg-zinc-900 px-3 py-2 text-xs font-mono text-teal-300 overflow-x-auto">
              {rawKey}
            </code>
            <button onClick={() => copyKey(rawKey)} className="shrink-0 rounded border border-zinc-700 p-2 hover:bg-zinc-800">
              <Copy className="h-4 w-4 text-zinc-400" />
            </button>
          </div>
          {copied && <p className="mt-1 text-xs text-teal-400">Copied!</p>}
          <button onClick={() => setRawKey(null)} className="mt-3 text-xs text-zinc-500 hover:text-zinc-300">Dismiss</button>
        </div>
      )}

      {/* Create new key */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        <p className="text-sm font-semibold text-zinc-300 mb-3">Create New Key</p>
        <div className="flex gap-2">
          <input
            value={newName}
            onChange={e => setNewName(e.target.value)}
            onKeyDown={e => e.key === "Enter" && createKey()}
            placeholder="Key name (e.g. CI Pipeline)"
            className="flex-1 rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-500 focus:outline-none focus:ring-1 focus:ring-teal-600"
          />
          <button
            onClick={createKey}
            disabled={creating || !newName.trim()}
            className="flex items-center gap-2 rounded-md bg-teal-700 px-4 py-2 text-sm font-medium text-white hover:bg-teal-600 disabled:opacity-50"
          >
            <Plus className="h-4 w-4" />
            {creating ? "Creating…" : "Create"}
          </button>
        </div>
      </div>

      {/* Keys table */}
      {loading ? (
        <div className="text-sm text-zinc-500">Loading…</div>
      ) : keys.length === 0 ? (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center text-sm text-zinc-500">
          No API keys yet. Create one above.
        </div>
      ) : (
        <div className="rounded-lg border border-zinc-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900 text-xs uppercase tracking-wide text-zinc-500">
              <tr>
                <th className="px-4 py-3 text-left">Name</th>
                <th className="px-4 py-3 text-left">Prefix</th>
                <th className="px-4 py-3 text-left">Scopes</th>
                <th className="px-4 py-3 text-left">Last Used</th>
                <th className="px-4 py-3 text-left">Created</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800 bg-zinc-950">
              {keys.map(k => (
                <tr key={k.id} className="hover:bg-zinc-900/50">
                  <td className="px-4 py-3 font-medium text-zinc-200">{k.name}</td>
                  <td className="px-4 py-3 font-mono text-zinc-400 text-xs">{k.keyPrefix}…</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {k.scopes.map(s => (
                        <span key={s} className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{s}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-zinc-500 text-xs">
                    {k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleDateString() : "Never"}
                  </td>
                  <td className="px-4 py-3 text-zinc-500 text-xs">
                    {new Date(k.createdAt).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => revokeKey(k.id)}
                      className="inline-flex items-center gap-1 rounded border border-red-900 px-2 py-1 text-xs text-red-400 hover:bg-red-950"
                    >
                      <Trash2 className="h-3 w-3" />
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
