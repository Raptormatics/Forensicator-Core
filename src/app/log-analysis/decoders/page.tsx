"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import {
  AlertCircle, CheckCircle2, ChevronDown, ChevronRight, Code2,
  Copy, Lock, Plus, RefreshCw, Settings, Trash2,
} from "lucide-react";

type Decoder = {
  id: string;
  name: string;
  title: string | null;
  description: string | null;
  enabled: boolean;
  isBuiltin: boolean;
  version: number;
  createdAt: string;
  updatedAt: string;
  createdBy: { email: string; name: string | null } | null;
  organization: { id: string; name: string } | null;
};

type GroupedDecoders = {
  custom:  Decoder[];
  builtin: Decoder[];
};

/** Extract the vendor label from a decoder name like decoder/apache-access/0 */
function extractVendor(name: string): string {
  const mid    = name.split("/")[1] ?? name;
  const vendor = mid.split("-")[0] ?? mid;
  return vendor.charAt(0).toUpperCase() + vendor.slice(1);
}

export default function DecodersPage() {
  const { data: session }                 = useSession();
  const isPlatformAdmin                   = (session?.user as { role?: string })?.role === "platform_admin";

  const [decoders, setDecoders]           = useState<GroupedDecoders>({ custom: [], builtin: [] });
  const [loading, setLoading]             = useState(true);
  const [builtinExpanded, setBuiltinExpanded] = useState(false);
  const [seeding, setSeeding]             = useState(false);
  const [seedMsg, setSeedMsg]             = useState<string | null>(null);
  const [deleteError, setDeleteError]     = useState<string | null>(null);

  /** Decoders grouped by vendor, sorted alphabetically */
  const vendorGroups = useMemo(() => {
    const groups: Record<string, Decoder[]> = {};
    for (const d of decoders.builtin) {
      const v = extractVendor(d.name);
      (groups[v] ??= []).push(d);
    }
    return Object.entries(groups).sort(([a], [b]) => a.localeCompare(b));
  }, [decoders.builtin]);

  async function load() {
    setLoading(true);
    try {
      const res  = await fetch("/api/log-analysis/decoders");
      const data = await res.json();
      const all: Decoder[] = data.decoders ?? [];
      setDecoders({
        custom:  all.filter((d) => !d.isBuiltin),
        builtin: all.filter((d) =>  d.isBuiltin),
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function toggleEnabled(d: Decoder) {
    await fetch(`/api/log-analysis/decoders/${d.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !d.enabled }),
    });
    load();
  }

  async function deleteDecoder(d: Decoder) {
    const label = d.isBuiltin ? `Remove built-in decoder "${d.name}" from the database? It will be restored next time you run "Seed Built-ins".` : `Delete decoder "${d.name}"? This cannot be undone.`;
    if (!confirm(label)) return;
    setDeleteError(null);
    const res = await fetch(`/api/log-analysis/decoders/${d.id}`, { method: "DELETE" });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setDeleteError(body.error ?? `Delete failed (${res.status})`);
      return;
    }
    load();
  }

  async function cloneDecoder(d: Decoder) {
    const res = await fetch(`/api/log-analysis/decoders/${d.id}/clone`, { method: "POST" });
    if (res.ok) {
      load();
    } else {
      const body = await res.json();
      alert(body.error ?? "Clone failed");
    }
  }

  async function seedBuiltins() {
    setSeeding(true);
    setSeedMsg(null);
    try {
      const res  = await fetch("/api/log-analysis/decoders/seed", { method: "POST" });
      const data = await res.json();
      setSeedMsg(`Seeded ${data.seeded?.length ?? 0} decoder(s). ${data.errors?.length ? `${data.errors.length} error(s).` : ""}`);
      load();
    } finally {
      setSeeding(false);
    }
  }

  const customCount  = decoders.custom.length;
  const builtinCount = decoders.builtin.length;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <div className="max-w-5xl mx-auto px-4 py-8">

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <Code2 className="h-7 w-7 text-teal-400" />
            <div>
              <h1 className="text-2xl font-bold">Log Decoders</h1>
              <p className="text-sm text-zinc-400 mt-0.5">YAML-based log source integrations</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={seedBuiltins}
              disabled={seeding}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${seeding ? "animate-spin" : ""}`} />
              Seed Built-ins
            </button>
            <Link
              href="/log-analysis/decoders/new"
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg bg-teal-600 hover:bg-teal-500 text-white font-medium transition-colors"
            >
              <Plus className="h-4 w-4" />
              New Decoder
            </Link>
          </div>
        </div>

        {seedMsg && (
          <div className="mb-4 flex items-center gap-2 px-4 py-2.5 rounded-lg bg-teal-900/30 border border-teal-800 text-teal-300 text-sm">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            {seedMsg}
          </div>
        )}

        {deleteError && (
          <div className="mb-4 flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {deleteError}
            <button onClick={() => setDeleteError(null)} className="ml-auto text-red-400 hover:text-red-200">&times;</button>
          </div>
        )}

        {loading ? (
          <div className="flex justify-center py-20">
            <RefreshCw className="h-6 w-6 animate-spin text-zinc-500" />
          </div>
        ) : (
          <div className="space-y-6">

            {/* Custom Decoders */}
            <section>
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">
                  Custom Decoders ({customCount})
                </h2>
              </div>

              {customCount === 0 ? (
                <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-10 text-center">
                  <Code2 className="mx-auto h-10 w-10 text-zinc-600 mb-3" />
                  <p className="text-zinc-400 text-sm">No custom decoders yet.</p>
                  <p className="text-zinc-500 text-sm mt-1">
                    Create one to add support for your log sources without changing code.
                  </p>
                  <Link
                    href="/log-analysis/decoders/new"
                    className="mt-4 inline-flex items-center gap-1.5 px-4 py-2 text-sm rounded-lg bg-teal-600 hover:bg-teal-500 text-white font-medium transition-colors"
                  >
                    <Plus className="h-4 w-4" />
                    Create your first decoder
                  </Link>
                </div>
              ) : (
                <div className="space-y-2">
                  {decoders.custom.map((d) => (
                    <DecoderCard
                      key={d.id}
                      decoder={d}
                      onToggle={() => toggleEnabled(d)}
                      onDelete={() => deleteDecoder(d)}
                      onClone={() => cloneDecoder(d)}
                    />
                  ))}
                </div>
              )}
            </section>

            {/* Built-in Decoders — grouped by vendor */}
            <section>
              <button
                onClick={() => setBuiltinExpanded((v) => !v)}
                className="flex items-center gap-2 text-sm font-semibold text-zinc-400 uppercase tracking-wider hover:text-zinc-200 transition-colors mb-3"
              >
                {builtinExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                Built-in Decoders ({builtinCount})
              </button>

              {builtinExpanded && (
                <div className="space-y-3">
                  {builtinCount === 0 ? (
                    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 px-5 py-4 text-sm text-zinc-500">
                      No built-in decoders found. Use &quot;Seed Built-ins&quot; to load them.
                    </div>
                  ) : (
                    vendorGroups.map(([vendor, items]) => (
                      <VendorGroup
                        key={vendor}
                        vendor={vendor}
                        decoders={items}
                        onToggle={toggleEnabled}
                        onDelete={deleteDecoder}
                        onClone={cloneDecoder}
                        canDelete={isPlatformAdmin}
                      />
                    ))
                  )}
                </div>
              )}
            </section>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Vendor Group ─────────────────────────────────────────────────────────────

function VendorGroup({
  vendor, decoders, onToggle, onDelete, onClone, canDelete,
}: {
  vendor:    string;
  decoders:  Decoder[];
  onToggle:  (d: Decoder) => void;
  onDelete:  (d: Decoder) => void;
  onClone:   (d: Decoder) => void;
  canDelete: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const enabledCount = decoders.filter((d) => d.enabled).length;

  return (
    <div className="rounded-xl border border-zinc-800 overflow-hidden">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center gap-3 px-4 py-2.5 bg-zinc-900 hover:bg-zinc-800/80 transition-colors"
      >
        {expanded
          ? <ChevronDown  className="h-4 w-4 text-zinc-500 shrink-0" />
          : <ChevronRight className="h-4 w-4 text-zinc-500 shrink-0" />
        }
        <span className="font-semibold text-sm text-zinc-200">{vendor}</span>
        <span className="ml-1 text-xs text-zinc-500">
          {enabledCount}/{decoders.length} enabled
        </span>
      </button>

      {expanded && (
        <div className="divide-y divide-zinc-800/70">
          {decoders.map((d) => (
            <DecoderCard
              key={d.id}
              decoder={d}
              onToggle={() => onToggle(d)}
              onDelete={() => onDelete(d)}
              onClone={() => onClone(d)}
              readonly
              canDelete={canDelete}
              flat
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Decoder Card ─────────────────────────────────────────────────────────────

function DecoderCard({
  decoder,
  onToggle,
  onDelete,
  onClone,
  readonly  = false,
  canDelete = false,
  flat      = false,
}: {
  decoder:   Decoder;
  onToggle:  () => void;
  onDelete:  () => void;
  onClone:   () => void;
  readonly?: boolean;
  canDelete?:boolean;
  flat?:     boolean;
}) {
  return (
    <div className={flat
      ? "flex items-center gap-4 bg-zinc-900/60 px-4 py-3 hover:bg-zinc-800/50 transition-colors"
      : "flex items-center gap-4 rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3 hover:border-zinc-700 transition-colors"
    }>
      {/* Enable toggle */}
      <button
        onClick={onToggle}
        title={decoder.enabled ? "Enabled — click to disable" : "Disabled — click to enable"}
        className="shrink-0"
      >
        {decoder.enabled
          ? <CheckCircle2 className="h-4.5 w-4.5 text-teal-400" />
          : <AlertCircle  className="h-4.5 w-4.5 text-zinc-600" />
        }
      </button>

      {/* Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-sm text-teal-300 truncate">{decoder.name}</span>
          {decoder.title && (
            <span className="text-sm text-zinc-300">{decoder.title}</span>
          )}
          {readonly && (
            <span className="flex items-center gap-1 text-xs text-zinc-500 bg-zinc-800 px-1.5 py-0.5 rounded">
              <Lock className="h-3 w-3" />built-in
            </span>
          )}
          {!decoder.enabled && (
            <span className="text-xs text-zinc-500 bg-zinc-800 px-1.5 py-0.5 rounded">disabled</span>
          )}
        </div>
        {decoder.description && (
          <p className="text-xs text-zinc-500 mt-0.5 truncate">{decoder.description}</p>
        )}
      </div>

      {/* Meta */}
      <div className="shrink-0 text-xs text-zinc-500 hidden sm:block">
        v{decoder.version}
      </div>
      <div className="shrink-0 text-xs text-zinc-500 hidden md:block">
        {new Date(decoder.updatedAt).toLocaleDateString()}
      </div>

      {/* Actions */}
      <div className="shrink-0 flex items-center gap-1">
        <Link
          href={`/log-analysis/decoders/${decoder.id}`}
          className="p-1.5 rounded hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 transition-colors"
          title="Edit"
        >
          <Settings className="h-4 w-4" />
        </Link>
        <button
          onClick={onClone}
          className="p-1.5 rounded hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 transition-colors"
          title="Clone decoder"
        >
          <Copy className="h-4 w-4" />
        </button>
        {(!readonly || canDelete) && (
          <button
            onClick={onDelete}
            className="p-1.5 rounded hover:bg-red-900/40 text-zinc-400 hover:text-red-400 transition-colors"
            title={readonly ? "Remove from database (restored on re-seed)" : "Delete decoder"}
          >
            <Trash2 className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
}
