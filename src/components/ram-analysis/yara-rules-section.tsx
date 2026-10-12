"use client";

import { useEffect, useMemo, useState } from "react";
import { useSession } from "next-auth/react";
import {
  AlertCircle, CheckCircle2, ChevronDown, ChevronRight,
  Edit2, Lock, Plus, RefreshCw, Trash2, X, Zap,
} from "lucide-react";
import { SEVERITY_OPTIONS, type RuleSeverity } from "@/lib/ram-analysis/types";

type YaraRule = {
  id: string; name: string; description: string | null; severity: string;
  enabled: boolean; isBuiltin: boolean; yaraSource: string; tags: string[];
  hitCount: number; createdAt: string;
  createdBy: { email: string; name: string | null } | null;
};

type GroupedRules = {
  custom:  YaraRule[];
  builtin: YaraRule[];
};

type YaraRuleDraft = Omit<YaraRule, "id" | "isBuiltin" | "hitCount" | "createdAt" | "createdBy">;

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-900/40 text-red-400 border-red-900",
  high:     "bg-orange-900/40 text-orange-400 border-orange-900",
  medium:   "bg-yellow-900/40 text-yellow-400 border-yellow-900",
  low:      "bg-blue-900/40 text-blue-400 border-blue-900",
  info:     "bg-zinc-800 text-zinc-400 border-zinc-700",
};

// ── Signature Editor Component ──────────────────────────────────────────────

function YaraRuleEditor({
  initial,
  onSave,
  onCancel,
}: {
  initial?: Partial<YaraRule>;
  onSave: (data: YaraRuleDraft) => Promise<void>;
  onCancel: () => void;
}) {
  const [name, setName]               = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [severity, setSeverity]       = useState<RuleSeverity>((initial?.severity as RuleSeverity) ?? "medium");
  const [yaraSource, setYaraSource]   = useState(initial?.yaraSource ?? "rule MyRule\n{\n    strings:\n        $s1 = \"example\" ascii wide nocase\n    condition:\n        any of them\n}\n");
  const [tags, setTags]               = useState<string[]>(initial?.tags ?? []);
  const [tagInput, setTagInput]       = useState("");
  const [saving, setSaving]           = useState(false);
  const [error, setError]             = useState("");

  function addTag(e: React.KeyboardEvent) {
    if (e.key === "Enter" && tagInput.trim()) {
      e.preventDefault();
      setTags((t) => [...new Set([...t, tagInput.trim().toLowerCase()])]);
      setTagInput("");
    }
  }
  function removeTag(t: string) { setTags((ts) => ts.filter((x) => x !== t)); }

  async function handleSave() {
    if (!name.trim()) { setError("Signature name is required"); return; }
    if (!yaraSource.trim()) { setError("Yara source is required"); return; }
    setSaving(true);
    setError("");
    try {
      await onSave({ name, description: description || null, severity, enabled: initial?.enabled ?? true, yaraSource, tags });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="rounded-xl border border-zinc-700 bg-zinc-900 p-6 space-y-6">
      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-950/20 border border-red-900/40 rounded-lg px-3 py-2">
          <AlertCircle className="h-4 w-4 shrink-0" /> {error}
        </div>
      )}

      {/* Name + Severity */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="sm:col-span-2">
          <label className="block text-xs text-zinc-400 mb-1.5">Signature Name *</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Known Loader Indicators"
            className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-teal-500"
          />
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1.5">Severity</label>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as RuleSeverity)}
            className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-teal-500"
          >
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Description */}
      <div>
        <label className="block text-xs text-zinc-400 mb-1.5">Description</label>
        <textarea
          value={description ?? ""}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="What does this signature detect?"
          rows={2}
          className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-teal-500 resize-none"
        />
      </div>

      {/* Yara source */}
      <div>
        <label className="block text-xs text-zinc-400 mb-1.5">Yara Source *</label>
        <textarea
          value={yaraSource}
          onChange={(e) => setYaraSource(e.target.value)}
          rows={12}
          className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs font-mono text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500 resize-y"
        />
        <p className="mt-1 text-xs text-zinc-600">Validated against the Volatility3 venv&apos;s yara-python on save.</p>
      </div>

      {/* Tags */}
      <div>
        <label className="block text-xs text-zinc-400 mb-1.5">Tags</label>
        <div className="flex flex-wrap items-center gap-2">
          {tags.map((t) => (
            <span key={t} className="flex items-center gap-1 rounded bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">
              {t}
              <button onClick={() => removeTag(t)}><X className="h-2.5 w-2.5" /></button>
            </span>
          ))}
          <input
            value={tagInput}
            onChange={(e) => setTagInput(e.target.value)}
            onKeyDown={addTag}
            placeholder="Add tag (Enter)"
            className="rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-300 placeholder-zinc-600 outline-none focus:border-teal-500"
          />
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between border-t border-zinc-800 pt-4">
        <button onClick={onCancel} className="text-sm text-zinc-500 hover:text-zinc-300">Cancel</button>
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 rounded-lg bg-teal-600 px-5 py-2 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50"
        >
          {saving ? <span className="animate-pulse">Saving…</span> : <><CheckCircle2 className="h-4 w-4" /> Save Signature</>}
        </button>
      </div>
    </div>
  );
}

export function YaraRulesSection() {
  const { data: session } = useSession();
  const isAdmin = ["platform_admin", "org_admin"].includes((session?.user as { role?: string })?.role ?? "");

  const [rules, setRules]       = useState<GroupedRules>({ custom: [], builtin: [] });
  const [loading, setLoading]   = useState(true);
  const [builtinExpanded, setBuiltinExpanded] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showNew, setShowNew]   = useState(false);
  const [editId, setEditId]     = useState<string | null>(null);
  const [seeding, setSeeding]   = useState(false);
  const [seedMsg, setSeedMsg]   = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  async function loadRules() {
    setLoading(true);
    try {
      const res  = await fetch("/api/ram-analysis/yara-rules");
      const data = await res.json();
      const all: YaraRule[] = data.rules ?? [];
      setRules({
        custom:  all.filter((r) => !r.isBuiltin),
        builtin: all.filter((r) =>  r.isBuiltin),
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadRules(); }, []);

  async function createRule(data: YaraRuleDraft) {
    const res = await fetch("/api/ram-analysis/yara-rules", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.message ?? body.error ?? `Create failed (${res.status})`);
    }
    setShowNew(false);
    loadRules();
  }

  async function updateRule(id: string, data: YaraRuleDraft) {
    const res = await fetch(`/api/ram-analysis/yara-rules/${id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.message ?? body.error ?? `Save failed (${res.status})`);
    }
    setEditId(null);
    loadRules();
  }

  async function toggleRule(rule: YaraRule) {
    await fetch(`/api/ram-analysis/yara-rules/${rule.id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    loadRules();
  }

  async function deleteRule(rule: YaraRule) {
    const label = rule.isBuiltin
      ? `Remove built-in signature "${rule.name}" from the database? It will be restored next time you run "Seed Built-ins".`
      : `Delete this Yara signature? Existing findings referencing it will be unlinked.`;
    if (!confirm(label)) return;
    setDeleteError(null);
    const res = await fetch(`/api/ram-analysis/yara-rules/${rule.id}`, { method: "DELETE" });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setDeleteError(body.error ?? `Delete failed (${res.status})`);
      return;
    }
    loadRules();
  }

  async function seedBuiltins() {
    setSeeding(true);
    setSeedMsg(null);
    try {
      const res  = await fetch("/api/ram-analysis/yara-rules/seed", { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        setSeedMsg(`Seed failed: ${data.detail ?? data.error ?? `HTTP ${res.status}`}`);
        return;
      }
      setSeedMsg(`Seeded ${data.seeded?.length ?? 0} signature(s). ${data.errors?.length ? `${data.errors.length} error(s).` : ""}`);
      loadRules();
    } finally {
      setSeeding(false);
    }
  }

  const customCount  = rules.custom.length;
  const builtinCount = rules.builtin.length;
  const totalEnabled = useMemo(
    () => [...rules.custom, ...rules.builtin].filter((r) => r.enabled).length,
    [rules]
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-zinc-100">Custom Yara Signatures</h2>
          <p className="mt-1 text-sm text-zinc-500 max-w-xl">
            Byte-pattern signatures scanned directly against the raw memory image, independent of Volatility3&apos;s process/connection model. Requires yara-python installed in the Volatility3 venv.
          </p>
          {(customCount + builtinCount) > 0 && (
            <div className="mt-2 flex gap-4 text-sm text-zinc-500">
              <span><span className="text-teal-400 font-medium">{totalEnabled}</span> enabled</span>
              <span><span className="text-zinc-600 font-medium">{customCount + builtinCount - totalEnabled}</span> disabled</span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={seedBuiltins}
            disabled={seeding}
            className="flex items-center gap-2 rounded-lg border border-zinc-700 px-4 py-2.5 text-sm font-medium text-zinc-300 hover:border-zinc-600 disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${seeding ? "animate-spin" : ""}`} /> Seed Built-ins
          </button>
          <button
            onClick={() => { setShowNew((v) => !v); setEditId(null); }}
            className="flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-500"
          >
            <Plus className="h-4 w-4" /> New Signature
          </button>
        </div>
      </div>

      {seedMsg && (
        <div className="flex items-center gap-2 text-sm text-teal-300 bg-teal-950/20 border border-teal-900/40 rounded-lg px-3 py-2">
          <CheckCircle2 className="h-4 w-4 shrink-0" /> {seedMsg}
        </div>
      )}
      {deleteError && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-950/20 border border-red-900/40 rounded-lg px-3 py-2">
          <AlertCircle className="h-4 w-4 shrink-0" /> {deleteError}
          <button onClick={() => setDeleteError(null)} className="ml-auto text-red-400 hover:text-red-200">&times;</button>
        </div>
      )}

      {showNew && (
        <YaraRuleEditor onSave={createRule} onCancel={() => setShowNew(false)} />
      )}

      {loading ? (
        <div className="flex items-center justify-center py-16 text-zinc-500">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-zinc-700 border-t-teal-400" />
        </div>
      ) : (
        <div className="space-y-6">
          {/* Custom Signatures */}
          <div>
            <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">
              Custom Signatures ({customCount})
            </h3>
            {customCount === 0 && !showNew ? (
              <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-zinc-700 py-8 text-center">
                <p className="text-sm text-zinc-400 font-medium">No custom signatures yet</p>
                <p className="text-xs text-zinc-600 mt-1 max-w-sm mb-4">
                  Core ships the built-in signatures below — write your own to match
                  indicators specific to your environment.
                </p>
                <button
                  onClick={() => setShowNew(true)}
                  className="flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500"
                >
                  <Plus className="h-4 w-4" /> Create Signature
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                {rules.custom.map((rule) => (
                  editId === rule.id ? (
                    <YaraRuleEditor
                      key={rule.id}
                      initial={rule}
                      onSave={(data) => updateRule(rule.id, data)}
                      onCancel={() => setEditId(null)}
                    />
                  ) : (
                    <YaraRuleCard
                      key={rule.id}
                      rule={rule}
                      expanded={expanded === rule.id}
                      onExpand={() => setExpanded(expanded === rule.id ? null : rule.id)}
                      onToggle={() => toggleRule(rule)}
                      onEdit={() => { setEditId(rule.id); setShowNew(false); }}
                      onDelete={() => deleteRule(rule)}
                      canDelete
                    />
                  )
                ))}
              </div>
            )}
          </div>

          {/* Built-in Signatures */}
          <div>
            <button
              onClick={() => setBuiltinExpanded((v) => !v)}
              className="flex items-center gap-2 text-xs font-medium text-zinc-500 uppercase tracking-wider hover:text-zinc-300 transition-colors mb-3"
            >
              {builtinExpanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
              Built-in Signatures ({builtinCount})
            </button>
            {builtinExpanded && (
              builtinCount === 0 ? (
                <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 px-5 py-4 text-sm text-zinc-500">
                  No built-in signatures found. Use &quot;Seed Built-ins&quot; to load them.
                </div>
              ) : (
                <div className="space-y-3">
                  {rules.builtin.map((rule) => (
                    <YaraRuleCard
                      key={rule.id}
                      rule={rule}
                      expanded={expanded === rule.id}
                      onExpand={() => setExpanded(expanded === rule.id ? null : rule.id)}
                      onToggle={() => toggleRule(rule)}
                      onDelete={() => deleteRule(rule)}
                      canDelete={isAdmin}
                    />
                  ))}
                </div>
              )
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function YaraRuleCard({
  rule, expanded, onExpand, onToggle, onEdit, onDelete, canDelete,
}: {
  rule:      YaraRule;
  expanded:  boolean;
  onExpand:  () => void;
  onToggle:  () => void;
  onEdit?:   () => void;
  onDelete:  () => void;
  canDelete: boolean;
}) {
  return (
    <div className={`rounded-xl border bg-zinc-900 ${rule.enabled ? "border-zinc-800" : "border-zinc-800/50 opacity-60"}`}>
      <div className="flex items-center gap-3 p-4">
        <button onClick={onExpand} className="text-zinc-600 hover:text-zinc-400">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        <span className={`rounded border px-1.5 py-0.5 text-xs capitalize ${SEVERITY_BADGE[rule.severity] ?? SEVERITY_BADGE.info}`}>
          {rule.severity}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-medium text-zinc-100">{rule.name}</p>
            {rule.isBuiltin && (
              <span className="flex items-center gap-1 text-xs text-zinc-500 bg-zinc-800 px-1.5 py-0.5 rounded">
                <Lock className="h-3 w-3" />built-in
              </span>
            )}
          </div>
          {rule.description && <p className="text-xs text-zinc-500 mt-0.5 truncate">{rule.description}</p>}
          {rule.hitCount > 0 && (
            <div className="mt-1 flex items-center gap-1 text-xs text-teal-600">
              <Zap className="h-3 w-3" /> {rule.hitCount} hits
            </div>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          {rule.tags.slice(0, 3).map((t) => (
            <span key={t} className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-600">{t}</span>
          ))}
          <button
            onClick={onToggle}
            title={rule.enabled ? "Disable" : "Enable"}
            className={`ml-2 rounded px-2 py-1 text-xs border transition-colors ${
              rule.enabled ? "border-teal-800 text-teal-500 hover:bg-teal-900/30" : "border-zinc-700 text-zinc-600 hover:border-zinc-600"
            }`}
          >
            {rule.enabled ? "Enabled" : "Disabled"}
          </button>
          {onEdit && (
            <button
              onClick={onEdit}
              className="p-1.5 rounded text-zinc-600 hover:text-zinc-300 hover:bg-zinc-800"
              title="Edit"
            >
              <Edit2 className="h-3.5 w-3.5" />
            </button>
          )}
          {canDelete && (
            <button
              onClick={onDelete}
              className="p-1.5 rounded text-zinc-600 hover:text-red-400 hover:bg-red-900/20"
              title={rule.isBuiltin ? "Remove from database (restored on re-seed)" : "Delete signature"}
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>
      {expanded && (
        <div className="border-t border-zinc-800 px-4 py-3">
          <pre className="rounded-lg bg-zinc-950 border border-zinc-800 p-3 text-xs font-mono text-zinc-300 overflow-x-auto whitespace-pre">
            {rule.yaraSource}
          </pre>
        </div>
      )}
    </div>
  );
}
