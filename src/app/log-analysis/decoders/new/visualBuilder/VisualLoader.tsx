"use client";

import { useState } from "react";
import { AlertCircle, Wand2 } from "lucide-react";
import { reverseParseDecoder, type ReverseParseResult, type ReverseParseError } from "./reverseParse";

const REASON_MESSAGES: Record<ReverseParseError["reason"], string> = {
  "no-pattern": "This decoder doesn't use the pattern-based parser (for example, it may be JSON-based) — visual editing isn't available for it. Use the raw YAML editor instead.",
  "multi-pattern": "This decoder has more than one fallback pattern. The visual editor only supports a single pattern, and loading it here would discard the others when you save — edit the raw YAML instead.",
  "no-match": "That sample line doesn't match this decoder's pattern (or its check: condition). Try a different line that this decoder actually parses, or check the raw YAML.",
  "yaml-error": "Couldn't parse this decoder's YAML.",
};

interface VisualLoaderProps {
  yamlContent: string;
  defaultSampleLine: string;
  onLoaded: (result: ReverseParseResult) => void;
}

export default function VisualLoader({ yamlContent, defaultSampleLine, onLoaded }: VisualLoaderProps) {
  const [sampleLine, setSampleLine] = useState(defaultSampleLine);
  const [error, setError] = useState<ReverseParseError | null>(null);

  function load() {
    if (!sampleLine.trim()) return;
    const result = reverseParseDecoder(yamlContent, sampleLine);
    if ("reason" in result) { setError(result); return; }
    setError(null);
    onLoaded(result);
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Wand2 className="h-4 w-4 text-teal-400" />
        <span className="text-sm font-semibold text-zinc-200">Load into Visual Editor</span>
      </div>
      <p className="text-xs text-zinc-500">
        Decoders don&apos;t store the sample line they were built from — paste one that this decoder actually
        matches, and its existing fields will be reconstructed for editing.
      </p>
      <textarea
        value={sampleLine}
        onChange={(e) => setSampleLine(e.target.value)}
        placeholder="Paste a raw log line this decoder matches…"
        rows={3}
        className="w-full font-mono text-sm bg-zinc-950 border border-zinc-700 rounded-lg p-3 text-zinc-200 outline-none focus:border-teal-500 resize-none"
      />
      {error && (
        <div className="flex items-start gap-2 text-xs text-orange-400 bg-orange-900/20 border border-orange-900/40 rounded-lg p-3">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>{REASON_MESSAGES[error.reason]}{error.reason === "yaml-error" && "detail" in error ? ` (${error.detail})` : ""}</span>
        </div>
      )}
      <button
        onClick={load}
        disabled={!sampleLine.trim()}
        className="flex items-center gap-1.5 rounded-md bg-teal-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <Wand2 className="h-3.5 w-3.5" /> Load
      </button>
    </div>
  );
}
