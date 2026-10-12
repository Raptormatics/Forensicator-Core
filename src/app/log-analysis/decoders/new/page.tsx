"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  AlertCircle, ArrowLeft, CheckCircle2, Code2, Loader2, Play, Save, Wand2, FileCode,
} from "lucide-react";
import VisualBuilder from "./visualBuilder/VisualBuilder";

const STARTER_YAML = `name: decoder/my-integration/0
enabled: true

metadata:
  title: 'My Custom Integration'
  author: ''
  date: '${new Date().toISOString().slice(0, 10)}'
  description: 'Describe what this decoder normalizes'

check: >-
  starts_with($event.original, 'MY_PREFIX')

# parse|event.original:
#   - '<source.ip> <destination.ip> <message>'

normalize:
  - map:
      - event.dataset: my.integration
      - event.kind: event
      - event.category: array_append(network)
      - observer.vendor: 'My Vendor'
      - observer.product: 'My Product'
`;

type ValidationResult = {
  valid: boolean;
  errors: string[];
  detectedFields: string[];
};

export default function NewDecoderPage() {
  const router = useRouter();
  const [mode, setMode]             = useState<"visual" | "yaml">("visual");
  const [yaml, setYaml]             = useState("");
  const [yamlManuallyEdited, setYamlManuallyEdited] = useState(false);
  const [saving, setSaving]         = useState(false);
  const [saveError, setSaveError]   = useState<string | null>(null);
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [orgId, setOrgId]           = useState<string | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  function switchToYamlMode() {
    if (!yaml.trim()) setYaml(STARTER_YAML);
    setMode("yaml");
  }

  function switchToVisualMode() {
    if (mode === "yaml" && yamlManuallyEdited) {
      if (!confirm("Switching to Visual Builder will discard your manual YAML edits and start over. Continue?")) return;
    }
    setMode("visual");
  }

  // Test harness
  const [logLine, setLogLine]   = useState("");
  const [testing, setTesting]   = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testErrors, setTestErrors] = useState<string[]>([]);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => validateYaml(yaml), 350);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [yaml]);

  async function validateYaml(content: string) {
    if (!content.trim()) return;
    setValidating(true);
    try {
      const res = await fetch("/api/log-analysis/decoders/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yamlContent: content, logLine: "__validation_probe__" }),
      });
      const data = await res.json();
      if (data.error === "validation") {
        setValidation({ valid: false, errors: [data.error], detectedFields: [] });
        return;
      }
      // If it compiled without error (even if check didn't match), it's valid
      const isInvalid = data.validationErrors?.some((e: string) => e.toLowerCase().includes("yaml") || e.toLowerCase().includes("must have"));
      const fields = data.output ? Object.keys(data.output).filter((k) => !k.startsWith("_") && k !== "event.original" && k !== "message") : [];
      setValidation({
        valid: !isInvalid,
        errors: isInvalid ? data.validationErrors ?? [] : [],
        detectedFields: fields,
      });
    } catch {
      setValidation({ valid: false, errors: ["Connection error during validation"], detectedFields: [] });
    } finally {
      setValidating(false);
    }
  }

  async function runTest() {
    if (!logLine.trim()) return;
    setTesting(true);
    setTestResult(null);
    setTestErrors([]);
    try {
      const res  = await fetch("/api/log-analysis/decoders/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yamlContent: yaml, logLine }),
      });
      const data = await res.json();
      setTestResult(data.output ? JSON.stringify(data.output, null, 2) : null);
      setTestErrors(data.validationErrors ?? []);
      if (!data.matched) setTestErrors((prev) => [...prev, data.validationErrors?.[0] ?? "No match"]);
    } finally {
      setTesting(false);
    }
  }

  async function save() {
    setSaving(true);
    setSaveError(null);
    try {
      const res  = await fetch("/api/log-analysis/decoders", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yamlContent: yaml, organizationId: orgId }),
      });
      const data = await res.json();
      if (!res.ok) {
        setSaveError(data.detail ? JSON.stringify(data.detail) : (data.error ?? "Save failed"));
        return;
      }
      router.push(`/log-analysis/decoders/${data.decoder.id}`);
    } finally {
      setSaving(false);
    }
  }

  const isValid = validation?.valid !== false && yaml.trim().length > 0;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <div className="max-w-6xl mx-auto px-4 py-8">

        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Link href="/log-analysis/decoders" className="p-1.5 rounded hover:bg-zinc-800 text-zinc-400">
              <ArrowLeft className="h-5 w-5" />
            </Link>
            <div className="flex items-center gap-2">
              <Code2 className="h-6 w-6 text-teal-400" />
              <h1 className="text-xl font-bold">New Decoder</h1>
            </div>
            <div className="ml-4 flex items-center rounded-lg border border-zinc-800 bg-zinc-900 p-0.5 text-sm">
              <button
                onClick={switchToVisualMode}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1 transition-colors ${
                  mode === "visual" ? "bg-teal-600 text-white" : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <Wand2 className="h-3.5 w-3.5" /> Visual Builder
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
          </div>
          <div className="flex items-center gap-2">
            <Link href="/log-analysis/decoders" className="px-3 py-1.5 text-sm rounded-lg bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 transition-colors">
              Cancel
            </Link>
            <button
              onClick={save}
              disabled={saving || !isValid}
              className="flex items-center gap-1.5 px-4 py-1.5 text-sm rounded-lg bg-teal-600 hover:bg-teal-500 text-white font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              Save Decoder
            </button>
          </div>
        </div>

        {saveError && (
          <div className="mb-4 flex items-start gap-2 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <span className="whitespace-pre-wrap">{saveError}</span>
          </div>
        )}

        {/* Main layout */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">

          {/* YAML Editor */}
          <div className="lg:col-span-3 flex flex-col gap-4">
            <div className={mode === "visual" ? "" : "hidden"}>
              <VisualBuilder onYamlChange={(y) => { setYaml(y); setYamlManuallyEdited(false); }} />
            </div>

            <div className={mode === "yaml" ? "rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden" : "hidden"}>
              <div className="flex items-center justify-between px-4 py-2.5 border-b border-zinc-800 bg-zinc-900/80">
                <span className="text-xs font-medium text-zinc-400 uppercase tracking-wider">decoder.yaml</span>
                {validating && <Loader2 className="h-3.5 w-3.5 animate-spin text-zinc-500" />}
              </div>
              <textarea
                value={yaml}
                onChange={(e) => { setYaml(e.target.value); setYamlManuallyEdited(true); }}
                spellCheck={false}
                className="w-full font-mono text-sm text-zinc-200 bg-zinc-950 p-4 h-[500px] resize-none outline-none leading-relaxed"
                placeholder="Paste or write your YAML decoder here…"
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
                    placeholder="Paste a raw log line to test…"
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
                {testErrors.length > 0 && (
                  <div className="flex items-start gap-2 text-sm text-orange-400 bg-orange-900/20 border border-orange-900/40 rounded-lg p-3">
                    <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                    <span>{testErrors.join(" · ")}</span>
                  </div>
                )}
                {testResult && (
                  <pre className="rounded-lg bg-zinc-950 border border-zinc-800 p-4 text-xs text-teal-300 overflow-x-auto max-h-64">
                    {testResult}
                  </pre>
                )}
              </div>
            </div>
          </div>

          {/* Validation Panel */}
          <div className="lg:col-span-2 space-y-4">
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <div className="flex items-center gap-2 mb-4">
                {validation === null || validating ? (
                  <Loader2 className="h-4 w-4 animate-spin text-zinc-500" />
                ) : validation.valid ? (
                  <CheckCircle2 className="h-4 w-4 text-teal-400" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-red-400" />
                )}
                <span className="text-sm font-medium">
                  {validation === null || validating ? "Validating…"
                    : validation.valid ? "Valid decoder" : "Validation errors"}
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

            {/* Reference card */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-3">Pattern Syntax</p>
              <div className="space-y-1.5 text-xs font-mono">
                {[
                  ["<field>",           "non-whitespace string"],
                  ["<field/long>",      "integer"],
                  ["<field/double>",    "float"],
                  ['<field/quoted/">',  "double-quoted string"],
                  ["<?field>",          "optional field"],
                  ["<~>",               "discard token"],
                ].map(([syn, desc]) => (
                  <div key={syn} className="flex gap-2">
                    <span className="text-teal-400 w-36 shrink-0">{syn}</span>
                    <span className="text-zinc-500">{desc}</span>
                  </div>
                ))}
              </div>

              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mt-4 mb-3">Functions</p>
              <div className="space-y-1.5 text-xs font-mono">
                {[
                  "parse_key_value($field, '=', ' ')",
                  "get_key_in($_kv, 'key')",
                  "array_append(value)",
                  "array_append_unique($field)",
                  "downcase($field)",
                  "parse_long($field)",
                  "concat($a, '', $b)",
                  "regex_extract($field, 'pattern')",
                  "delete()",
                ].map((fn) => (
                  <div key={fn} className="text-teal-400">{fn}</div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
