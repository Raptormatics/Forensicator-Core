"use client";

import { useMemo, useState } from "react";
import { AlertCircle, Check, Trash2, X } from "lucide-react";
import { compilePattern } from "@/lib/log-analysis/decoder-engine/patternParser";
import {
  type Span, type SpanType, SPAN_TYPE_LABELS, COMMON_FIELD_NAMES,
  suggestType, typeAllowsSpaces, genId,
} from "./patternBuilder";
import type { BoundaryResult } from "./textSelection";

interface SpanEditorPanelProps {
  rawLine: string;
  /** New span being created, from a fresh drag-selection. */
  boundary?: BoundaryResult;
  /** Existing span being edited instead. */
  existingSpan?: Span;
  existingPaths: string[];
  onConfirm: (span: Span) => void;
  onRemove?: () => void;
  onCancel: () => void;
}

export default function SpanEditorPanel({
  rawLine, boundary, existingSpan, existingPaths, onConfirm, onRemove, onCancel,
}: SpanEditorPanelProps) {
  const start = existingSpan?.start ?? boundary?.start ?? 0;
  const end = existingSpan?.end ?? boundary?.end ?? 0;
  const consumedBoundary = existingSpan?.consumedBoundary ?? boundary?.consumedBoundary ?? false;

  const innerText = useMemo(() => {
    if (consumedBoundary) return rawLine.slice(start + 1, end - 1);
    return rawLine.slice(start, end);
  }, [rawLine, start, end, consumedBoundary]);

  const [path, setPath] = useState(existingSpan?.path ?? "");
  const [type, setType] = useState<SpanType>(
    existingSpan?.type ?? suggestType(innerText, { quoteChar: boundary?.quoteChar, between: boundary?.between })
  );
  const [quoteChar, setQuoteChar] = useState<'"' | "'">(existingSpan?.quoteChar ?? boundary?.quoteChar ?? '"');
  const [between, setBetween] = useState(
    existingSpan?.between ?? boundary?.between ?? { open: "[", close: "]" }
  );

  const selectedText = rawLine.slice(start, end);
  const containsSpace = selectedText.includes(" ");
  const spaceBlocked = containsSpace && !typeAllowsSpaces(type);
  const pathRequired = type !== "discard";
  const pathMissing = pathRequired && path.trim() === "";
  const pathTaken = pathRequired && existingPaths.includes(path.trim()) && path.trim() !== existingSpan?.path;

  const preview = useMemo(() => {
    if (spaceBlocked || (pathRequired && pathMissing)) return null;
    const span: Span = {
      id: "preview", start, end,
      path: path.trim(), type, quoteChar, between,
      consumedBoundary,
    };
    let token: string;
    switch (span.type) {
      case "discard":  token = "<~>"; break;
      case "optional": token = `<?${span.path}>`; break;
      case "long":     token = `<${span.path}/long>`; break;
      case "double":   token = `<${span.path}/double>`; break;
      case "quoted":   token = `<${span.path}/quoted/${quoteChar}>`; break;
      case "between":  token = `<${span.path}/between/[${between.open}][${between.close}]>`; break;
      case "ISO8601":  token = `<${span.path}/ISO8601>`; break;
      case "SYSLOG":   token = `<${span.path}/SYSLOG>`; break;
      default:         token = `<${span.path}>`;
    }
    try {
      const compiled = compilePattern(token);
      const m = compiled.regex.exec(rawLine.slice(start, end));
      return m ? { ok: true, captured: m.groups ? Object.values(m.groups)[0] : m[0] } : { ok: false, captured: null };
    } catch {
      return { ok: false, captured: null };
    }
  }, [type, path, quoteChar, between, start, end, rawLine, spaceBlocked, pathRequired, pathMissing, consumedBoundary]);

  const canConfirm = !spaceBlocked && !pathMissing && !pathTaken;

  function confirm() {
    if (!canConfirm) return;
    onConfirm({
      id: existingSpan?.id ?? genId(),
      start, end,
      path: type === "discard" ? "" : path.trim(),
      type, quoteChar, between,
      consumedBoundary,
    });
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-sm font-semibold text-zinc-200">{existingSpan ? "Edit field" : "Add field"}</span>
        <button onClick={onCancel} className="text-zinc-500 hover:text-zinc-300"><X className="h-4 w-4" /></button>
      </div>

      <div className="rounded-lg bg-zinc-950 border border-zinc-800 px-3 py-2">
        <p className="text-xs text-zinc-500 mb-1">Selected text</p>
        <code className="text-sm text-teal-300 break-all">{rawLine.slice(start, end)}</code>
        {consumedBoundary && (
          <p className="text-xs text-zinc-500 mt-1.5">
            Extended by one character on each side to include its enclosing delimiter — this field will consume
            the delimiter itself rather than leaving it as separate literal text.
          </p>
        )}
      </div>

      {type !== "discard" && (
        <div>
          <label className="text-xs text-zinc-500 block mb-1">Field name</label>
          <input
            list="visual-builder-field-names"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="e.g. source.ip"
            className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 font-mono outline-none focus:border-teal-500"
          />
          <datalist id="visual-builder-field-names">
            {COMMON_FIELD_NAMES.map((f) => <option key={f} value={f} />)}
          </datalist>
          {pathTaken && <p className="text-xs text-red-400 mt-1">A field with this name is already tagged.</p>}
        </div>
      )}

      <div>
        <label className="text-xs text-zinc-500 block mb-1">Type</label>
        <select
          value={type}
          onChange={(e) => setType(e.target.value as SpanType)}
          className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 outline-none focus:border-teal-500"
        >
          {(Object.keys(SPAN_TYPE_LABELS) as SpanType[]).map((t) => (
            <option key={t} value={t}>{SPAN_TYPE_LABELS[t]}</option>
          ))}
        </select>
      </div>

      {type === "quoted" && (
        <div className="flex gap-4 text-sm text-zinc-300">
          <label className="flex items-center gap-1.5">
            <input type="radio" checked={quoteChar === '"'} onChange={() => setQuoteChar('"')} /> Double quote (&quot;)
          </label>
          <label className="flex items-center gap-1.5">
            <input type="radio" checked={quoteChar === "'"} onChange={() => setQuoteChar("'")} /> Single quote (&apos;)
          </label>
        </div>
      )}

      {type === "between" && (
        <div className="flex gap-3">
          <div className="flex-1">
            <label className="text-xs text-zinc-500 block mb-1">Opening delimiter</label>
            <input value={between.open} onChange={(e) => setBetween({ ...between, open: e.target.value })}
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 font-mono outline-none focus:border-teal-500" />
          </div>
          <div className="flex-1">
            <label className="text-xs text-zinc-500 block mb-1">Closing delimiter</label>
            <input value={between.close} onChange={(e) => setBetween({ ...between, close: e.target.value })}
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 font-mono outline-none focus:border-teal-500" />
          </div>
        </div>
      )}

      {spaceBlocked && (
        <div className="flex items-start gap-2 text-xs text-orange-400 bg-orange-900/20 border border-orange-900/40 rounded-lg p-3">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>
            This selection contains a space — choose &quot;Quoted string&quot; or &quot;Between delimiters&quot;
            (or extend the selection to include its enclosing delimiters), or the generated pattern won&apos;t be
            able to capture it.
          </span>
        </div>
      )}

      {!spaceBlocked && preview && (
        <div className={`flex items-start gap-2 text-xs rounded-lg p-3 border ${
          preview.ok ? "text-teal-300 bg-teal-900/20 border-teal-900/40" : "text-red-400 bg-red-900/20 border-red-900/40"
        }`}>
          {preview.ok ? <Check className="h-4 w-4 shrink-0 mt-0.5" /> : <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />}
          <span>{preview.ok ? `Captures: "${String(preview.captured)}"` : "This selection doesn't match the chosen type."}</span>
        </div>
      )}

      <div className="flex justify-between gap-2 pt-1">
        {existingSpan && onRemove ? (
          <button onClick={onRemove} className="flex items-center gap-1.5 rounded-md border border-red-900/60 px-3 py-1.5 text-sm text-red-400 hover:bg-red-900/20">
            <Trash2 className="h-3.5 w-3.5" /> Remove
          </button>
        ) : <span />}
        <div className="flex gap-2">
          <button onClick={onCancel} className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:bg-zinc-800">Cancel</button>
          <button onClick={confirm} disabled={!canConfirm}
            className="rounded-md bg-teal-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50 disabled:cursor-not-allowed">
            {existingSpan ? "Save" : "Add field"}
          </button>
        </div>
      </div>
    </div>
  );
}
