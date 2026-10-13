"use client";

import { useEffect, useMemo, useState, useRef } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, CheckCircle2, Code2, Copy, Lock, Loader2, Play, Save, Trash2, Wand2, FileCode,
} from "lucide-react";
import VisualBuilder from "../new/visualBuilder/VisualBuilder";
import VisualLoader from "../new/visualBuilder/VisualLoader";
import { canReverseParse, type ReverseParseResult } from "../new/visualBuilder/reverseParse";

type Decoder = {
  id: string;
  name: string;
  title: string | null;
  description: string | null;
  yamlContent: string;
  enabled: boolean;
  isBuiltin: boolean;
  version: number;
  createdAt: string;
  updatedAt: string;
  createdBy: { email: string; name: string | null } | null;
  organization: { id: string; name: string } | null;
};

type ValidationResult = {
  valid: boolean;
  errors: string[];
  detectedFields: string[];
};

export default function DecoderDetailPage() {
  const { id }    = useParams<{ id: string }>();
  const router    = useRouter();
  const [decoder, setDecoder]         = useState<Decoder | null>(null);
  const [yaml, setYaml]               = useState("");
  const [loading, setLoading]         = useState(true);
  const [saving, setSaving]           = useState(false);
  const [deleting, setDeleting]       = useState(false);
  const [saveError, setSaveError]     = useState<string | null>(null);
  const [saved, setSaved]             = useState(false);
  const [validation, setValidation]   = useState<ValidationResult | null>(null);
  const [validating, setValidating]   = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [mode, setMode]               = useState<"visual" | "yaml">("yaml");
  const [yamlManuallyEdited, setYamlManuallyEdited] = useState(false);
  const [visualSeed, setVisualSeed]   = useState<ReverseParseResult | null>(null);

  // Test harness
  const [logLine, setLogLine]       = useState("");
  const [testing, setTesting]       = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testMatched, setTestMatched] = useState<boolean | null>(null);
  const [testErrors, setTestErrors] = useState<string[]>([]);

  useEffect(() => {
    async function loadDecoder() {
      setLoading(true);
      try {
        const res  = await fetch(`/api/log-analysis/decoders/${id}`);
        const data = await res.json();
        if (data.decoder) {
          setDecoder(data.decoder);
          setYaml(data.decoder.yamlContent);
        }
      } finally {
        setLoading(false);
      }
    }
    loadDecoder();
  }, [id]);

  const reverseParseCheck = useMemo(
    () => (decoder ? canReverseParse(decoder.yamlContent) : { ok: false as const, reason: "yaml-error" as const }),
    [decoder]
  );

  useEffect(() => {
    if (!yaml) return;
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => validateYaml(yaml), 350);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [yaml]);

  async function validateYaml(content: string) {
    setValidating(true);
    try {
      const res  = await fetch("/api/log-analysis/decoders/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yamlContent: content, logLine: "__validation_probe__" }),
      });
      const data = await res.json();
      const isInvalid = data.validationErrors?.some((e: string) =>
        e.toLowerCase().includes("yaml") || e.toLowerCase().includes("must have")
      );
      const fields = data.output
        ? Object.keys(data.output).filter((k) => !k.startsWith("_") && k !== "event.original" && k !== "message")
        : [];
      setValidation({
        valid: !isInvalid,
        errors: isInvalid ? data.validationErrors ?? [] : [],
        detectedFields: fields,
      });
    } catch {
      setValidation({ valid: false, errors: ["Validation error"], detectedFields: [] });
    } finally {
      setValidating(false);
    }
  }

  async function runTest() {
    if (!logLine.trim()) return;
    setTesting(true);
    setTestResult(null);
    setTestErrors([]);
    setTestMatched(null);
    try {
      const res  = await fetch("/api/log-analysis/decoders/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yamlContent: yaml, logLine }),
      });
      const data = await res.json();
      setTestMatched(data.matched ?? false);
      setTestResult(data.output ? JSON.stringify(data.output, null, 2) : null);
      setTestErrors(data.validationErrors ?? []);
    } finally {
      setTesting(false);
    }
  }

  async function save() {
    if (!decoder) return;
    setSaving(true);
    setSaveError(null);
    setSaved(false);
    try {
      const res  = await fetch(`/api/log-analysis/decoders/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yamlContent: yaml }),
      });
      const data = await res.json();
      if (!res.ok) {
        setSaveError(data.detail ? JSON.stringify(data.detail) : (data.error ?? "Save failed"));
        return;
      }
      setDecoder(data.decoder);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } finally {
      setSaving(false);
    }
  }

  async function toggleEnabled() {
    if (!decoder) return;
    const res  = await fetch(`/api/log-analysis/decoders/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !decoder.enabled }),
    });
    const data = await res.json();
    if (res.ok) setDecoder(data.decoder);
  }

  async function cloneDecoder() {
    const res  = await fetch(`/api/log-analysis/decoders/${id}/clone`, { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      router.push(`/log-analysis/decoders/${data.decoder.id}`);
    } else {
      alert(data.error ?? "Clone failed");
    }
  }

  async function deleteDecoder() {
    if (!confirm(`Delete decoder "${decoder?.name}"? This cannot be undone.`)) return;
    setDeleting(true);
    await fetch(`/api/log-analysis/decoders/${id}`, { method: "DELETE" });
    router.push("/log-analysis/decoders");
  }

  function switchToYamlMode() {
    setMode("yaml");
  }

  function switchToVisualMode() {
    if (visualSeed && yamlManuallyEdited) {
      if (!confirm("Switching to the Visual Editor will discard your manual YAML edits. Continue?")) return;
    }
    setMode("visual");
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-zinc-500" />
      </div>
    );
  }

  if (!decoder) {
    return (
      <div className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="mx-auto h-10 w-10 text-zinc-600 mb-3" />
          <p className="text-zinc-400">Decoder not found.</p>
          <Link href="/log-analysis/decoders" className="mt-3 inline-block text-teal-400 hover:underline text-sm">
            Back to Decoders
          </Link>
        </div>
      </div>
    );
  }

  // Editing and deleting built-ins is unrestricted — Core has no RBAC.
  const isReadonly = false;
  const canDelete  = true;
  const isValid    = validation?.valid !== false;
  const isDirty    = yaml !== decoder.yamlContent;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <div className="max-w-6xl mx-auto px-4 py-8">

        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Link href="/log-analysis/decoders" className="p-1.5 rounded hover:bg-zinc-800 text-zinc-400">
              <ArrowLeft className="h-5 w-5" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <Code2 className="h-5 w-5 text-teal-400" />
                <h1 className="text-lg font-bold font-mono">{decoder.name}</h1>
                {decoder.isBuiltin && (
                  <span className="flex items-center gap-1 text-xs text-zinc-500 bg-zinc-800 px-1.5 py-0.5 rounded">
                    <Lock className="h-3 w-3" />built-in
                  </span>
                )}
                {!decoder.enabled && (
                  <span className="text-xs text-zinc-500 bg-zinc-800 px-1.5 py-0.5 rounded">disabled</span>
                )}
              </div>
              {decoder.title && <p className="text-sm text-zinc-400 ml-7">{decoder.title}</p>}
            </div>
            {!isReadonly && (
              <div className="ml-2 flex items-center rounded-lg border border-zinc-800 bg-zinc-900 p-0.5 text-sm">
                <button
                  onClick={switchToVisualMode}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1 transition-colors ${
                    mode === "visual" ? "bg-teal-600 text-white" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Wand2 className="h-3.5 w-3.5" /> Visual Editor
                </button>
                <button
                  onClick={switchToYamlMode}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1 transition-colors ${
                    mode === "yaml" ? "bg-teal-600 text-white" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <FileCode className="h-3.5 w-3.5" /> Raw YAML
                </button>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={toggleEnabled}
              className="px-3 py-1.5 text-sm rounded-lg bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 transition-colors"
            >
              {decoder.enabled ? "Disable" : "Enable"}
            </button>
            <button
              onClick={cloneDecoder}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 transition-colors"
            >
              <Copy className="h-4 w-4" />
              Clone
            </button>
            {canDelete && (
              <button
                onClick={deleteDecoder}
                disabled={deleting}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg border border-red-900 text-red-400 hover:bg-red-900/30 transition-colors"
              >
                <Trash2 className="h-4 w-4" />
                Delete
              </button>
            )}
            {!isReadonly && (
              <button
                onClick={save}
                disabled={saving || !isValid || !isDirty}
                className="flex items-center gap-1.5 px-4 py-1.5 text-sm rounded-lg bg-teal-600 hover:bg-teal-500 text-white font-medium transition-colors disabled:opacity-50"
              >
                {saving  ? <Loader2      className="h-4 w-4 animate-spin" /> :
                 saved   ? <CheckCircle2 className="h-4 w-4" /> :
                           <Save         className="h-4 w-4" />}
                {saved ? "Saved!" : "Save"}
              </button>
            )}
          </div>
        </div>

        {/* Meta strip */}
        <div className="flex flex-wrap gap-4 text-xs text-zinc-500 mb-6">
          <span>Version {decoder.version}</span>
          <span>Updated {new Date(decoder.updatedAt).toLocaleString()}</span>
          {decoder.createdBy && <span>By {decoder.createdBy.name ?? decoder.createdBy.email}</span>}
          {decoder.organization && <span>Org: {decoder.organization.name}</span>}
        </div>

        {saveError && (
          <div className="mb-4 flex items-start gap-2 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <span>{saveError}</span>
          </div>
        )}

        {/* Main layout */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">

          {/* YAML Editor */}
          <div className="lg:col-span-3 flex flex-col gap-4">
            {!isReadonly && (
              <div className={mode === "visual" ? "" : "hidden"}>
                {!reverseParseCheck.ok ? (
                  <div className="flex items-start gap-2 text-sm text-orange-400 bg-orange-900/20 border border-orange-900/40 rounded-lg p-4">
                    <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                    <span>
                      {reverseParseCheck.reason === "no-pattern" &&
                        "This decoder doesn't use the pattern-based parser (for example, it may be JSON-based) — visual editing isn't available for it."}
                      {reverseParseCheck.reason === "multi-pattern" &&
                        "This decoder has more than one fallback pattern. The visual editor only supports a single pattern, and loading it here would discard the others on save."}
                      {reverseParseCheck.reason === "yaml-error" &&
                        "This decoder's YAML couldn't be parsed for visual editing."}
                      {" "}Use the Raw YAML tab instead.
                    </span>
                  </div>
                ) : visualSeed ? (
                  <VisualBuilder
                    key={decoder.id}
                    initial={{ rawLine: visualSeed.rawLine, spans: visualSeed.spans, meta: visualSeed.meta }}
                    existingName={visualSeed.name}
                    onYamlChange={(y) => { setYaml(y); setYamlManuallyEdited(false); }}
                  />
                ) : (
                  <VisualLoader
                    yamlContent={decoder.yamlContent}
                    defaultSampleLine={logLine}
                    onLoaded={setVisualSeed}
                  />
                )}
              </div>
            )}

            <div className={(isReadonly || mode === "yaml") ? "rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden" : "hidden"}>
              <div className="flex items-center justify-between px-4 py-2.5 border-b border-zinc-800 bg-zinc-900/80">
                <span className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
                  {decoder.name}.yaml {isDirty && !isReadonly && <span className="text-yellow-400">●</span>}
                </span>
                {validating && <Loader2 className="h-3.5 w-3.5 animate-spin text-zinc-500" />}
              </div>
              <textarea
                value={yaml}
                onChange={(e) => { if (!isReadonly) { setYaml(e.target.value); setYamlManuallyEdited(true); } }}
                readOnly={isReadonly}
                spellCheck={false}
                className={`w-full font-mono text-sm text-zinc-200 bg-zinc-950 p-4 h-[500px] resize-none outline-none leading-relaxed ${isReadonly ? "cursor-default opacity-80" : ""}`}
              />
            </div>

            {/* Test Panel */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
              <div className="px-4 py-2.5 border-b border-zinc-800 bg-zinc-900/80">
                <span className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Test Harness</span>
              </div>
              <div className="p-4 space-y-3">
                <div>
                  <label className="text-xs text-zinc-500 block mb-1">Sample log line</label>
                  <textarea
                    value={logLine}
                    onChange={(e) => setLogLine(e.target.value)}
                    placeholder="Paste a raw log line to test against this decoder…"
                    rows={3}
                    className="w-full font-mono text-sm bg-zinc-950 border border-zinc-700 rounded-lg p-3 text-zinc-200 outline-none focus:border-zinc-500 resize-none"
                  />
                </div>
                <button
                  onClick={runTest}
                  disabled={testing || !logLine.trim()}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg bg-zinc-700 hover:bg-zinc-600 text-white transition-colors disabled:opacity-50"
                >
                  {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                  Run Test
                </button>

                {testMatched === true && (
                  <div className="flex items-center gap-2 text-sm text-teal-400 bg-teal-900/20 border border-teal-900/40 rounded-lg px-3 py-2">
                    <CheckCircle2 className="h-4 w-4 shrink-0" />
                    Decoder matched
                  </div>
                )}
                {testMatched === false && (
                  <div className="flex items-center gap-2 text-sm text-orange-400 bg-orange-900/20 border border-orange-900/40 rounded-lg px-3 py-2">
                    <AlertCircle className="h-4 w-4 shrink-0" />
                    {testErrors[0] ?? "No decoder matched this log line"}
                  </div>
                )}

                {testResult && (
                  <pre className="rounded-lg bg-zinc-950 border border-zinc-800 p-4 text-xs text-teal-300 overflow-x-auto max-h-72">
                    {testResult}
                  </pre>
                )}

                {testErrors.filter((_, i) => i > 0 || testMatched !== false).length > 0 && (
                  <div className="text-xs text-yellow-400 space-y-1">
                    {testErrors.filter((_, i) => i > 0 || testMatched !== false).map((e, i) => (
                      <p key={i}>{e}</p>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Validation Panel */}
          <div className="lg:col-span-2 space-y-4">
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <div className="flex items-center gap-2 mb-4">
                {validating ? (
                  <Loader2 className="h-4 w-4 animate-spin text-zinc-500" />
                ) : validation?.valid ? (
                  <CheckCircle2 className="h-4 w-4 text-teal-400" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-red-400" />
                )}
                <span className="text-sm font-medium">
                  {validating ? "Validating…" : validation?.valid ? "Valid decoder" : "Validation errors"}
                </span>
              </div>

              {validation?.errors && validation.errors.length > 0 && (
                <div className="space-y-1 mb-4">
                  {validation.errors.map((e, i) => (
                    <p key={i} className="text-xs text-red-400 bg-red-900/20 rounded px-2 py-1">{e}</p>
                  ))}
                </div>
              )}

              {validation?.detectedFields && validation.detectedFields.length > 0 && (
                <div>
                  <p className="text-xs text-zinc-500 mb-2">Fields detected in normalize:</p>
                  <div className="flex flex-wrap gap-1">
                    {validation.detectedFields.map((f) => (
                      <span key={f} className="text-xs bg-zinc-800 text-teal-300 px-2 py-0.5 rounded font-mono">{f}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Reference */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-3">Check Functions</p>
              <div className="space-y-1 text-xs font-mono text-zinc-500">
                {[
                  "starts_with($field, 'prefix')",
                  "contains($field, 'substr')",
                  "string_equal($field, 'val')",
                  "regex_match($field, 'pattern')",
                  "exists($field)",
                  "not_exists($field)",
                  "$field == value",
                  "$field != value",
                  "expr AND expr",
                  "expr OR expr",
                ].map((fn) => <p key={fn}>{fn}</p>)}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
