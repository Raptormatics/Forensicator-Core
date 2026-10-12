"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { AlertCircle, MousePointerClick, Tag } from "lucide-react";
import {
  type Span, type DecoderMeta, EVENT_CATEGORIES,
  buildDecoderYaml, buildCheck, findStrayAngleBrackets, SPAN_TYPE_LABELS,
} from "./patternBuilder";
import { getAbsoluteSelectionOffsets, normalizeSpanBoundaries, type BoundaryResult } from "./textSelection";
import SpanEditorPanel from "./SpanEditorPanel";

interface VisualBuilderProps {
  onYamlChange: (yaml: string) => void;
  /**
   * Seeds the editor's initial state (e.g. from reverse-parsing an existing
   * decoder) — read only once, on mount. To load a *different* seed later,
   * remount this component with a changed `key` prop rather than expecting
   * a prop update to reset state.
   */
  initial?: { rawLine: string; spans: Span[]; meta: DecoderMeta };
  /** When editing an existing decoder, its current name: — kept stable across saves. */
  existingName?: string;
}

type EditorState =
  | { mode: "new"; boundary: BoundaryResult }
  | { mode: "edit"; span: Span }
  | null;

export default function VisualBuilder({ onYamlChange, initial, existingName }: VisualBuilderProps) {
  const [rawLine, setRawLine] = useState(initial?.rawLine ?? "");
  const [spans, setSpans] = useState<Span[]>(initial?.spans ?? []);
  const [editor, setEditor] = useState<EditorState>(null);
  const [overlapError, setOverlapError] = useState<string | null>(null);

  const [title, setTitle] = useState(initial?.meta.title ?? "");
  const [author, setAuthor] = useState(initial?.meta.author ?? "");
  const [description, setDescription] = useState(initial?.meta.description ?? "");
  const [category, setCategory] = useState<string>(initial?.meta.category ?? EVENT_CATEGORIES[0]);

  const containerRef = useRef<HTMLDivElement>(null);

  const meta: DecoderMeta = useMemo(() => ({ title, author, description, category }), [title, author, description, category]);

  const check = useMemo(() => buildCheck(rawLine, spans), [rawLine, spans]);
  const strayWarning = useMemo(() => findStrayAngleBrackets(rawLine, spans), [rawLine, spans]);

  useEffect(() => {
    if (!rawLine.trim()) { onYamlChange(""); return; }
    onYamlChange(buildDecoderYaml(meta, rawLine, spans, existingName));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rawLine, spans, meta, existingName]);

  function handleMouseUp() {
    if (!containerRef.current) return;
    const raw = getAbsoluteSelectionOffsets(containerRef.current);
    window.getSelection()?.removeAllRanges();
    if (!raw) return;

    const overlaps = spans.some((s) => raw.start < s.end && raw.end > s.start);
    if (overlaps) {
      setOverlapError("That selection overlaps a field you've already tagged — edit or remove it first.");
      return;
    }
    setOverlapError(null);

    const boundary = normalizeSpanBoundaries(rawLine, raw.start, raw.end);
    setEditor({ mode: "new", boundary });
  }

  function confirmSpan(span: Span) {
    setSpans((prev) => {
      const withoutOld = prev.filter((s) => s.id !== span.id);
      return [...withoutOld, span].sort((a, b) => a.start - b.start);
    });
    setEditor(null);
  }

  function removeSpan(id: string) {
    setSpans((prev) => prev.filter((s) => s.id !== id));
    setEditor(null);
  }

  const highlighted = useMemo(() => {
    if (!rawLine) return null;
    const sorted = [...spans].sort((a, b) => a.start - b.start);
    const nodes: React.ReactNode[] = [];
    let cursor = 0;
    for (const span of sorted) {
      if (span.start > cursor) nodes.push(<span key={`gap-${span.id}`}>{rawLine.slice(cursor, span.start)}</span>);
      nodes.push(
        <mark
          key={span.id}
          onClick={(e) => { e.stopPropagation(); setEditor({ mode: "edit", span }); }}
          className={`cursor-pointer rounded px-0.5 ${
            span.type === "discard"
              ? "bg-zinc-700 text-zinc-400 line-through decoration-zinc-500"
              : "bg-teal-900/50 text-teal-200 hover:bg-teal-900/70"
          }`}
          title={span.type === "discard" ? "discarded" : span.path}
        >
          {rawLine.slice(span.start, span.end)}
        </mark>
      );
      cursor = span.end;
    }
    if (cursor < rawLine.length) nodes.push(<span key="gap-last">{rawLine.slice(cursor)}</span>);
    return nodes;
  }, [rawLine, spans]);

  const existingPaths = spans.filter((s) => s.type !== "discard").map((s) => s.path);

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
        <div className="px-4 py-2.5 border-b border-zinc-800 bg-zinc-900/80">
          <span className="text-xs font-medium text-zinc-400 uppercase tracking-wider">1. Paste a sample log line</span>
        </div>
        <div className="p-4">
          <textarea
            value={rawLine}
            onChange={(e) => { setRawLine(e.target.value.replace(/\n/g, " ")); setSpans([]); setEditor(null); }}
            placeholder='e.g. 192.168.1.1 - - [24/Jun/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612'
            rows={2}
            spellCheck={false}
            className="w-full font-mono text-sm bg-zinc-950 border border-zinc-700 rounded-lg p-3 text-zinc-200 outline-none focus:border-teal-500 resize-none"
          />
        </div>
      </div>

      {rawLine.trim() && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
          <div className="px-4 py-2.5 border-b border-zinc-800 bg-zinc-900/80 flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-400 uppercase tracking-wider">2. Highlight the tokens you care about</span>
            <span className="flex items-center gap-1.5 text-xs text-zinc-500">
              <MousePointerClick className="h-3.5 w-3.5" /> Click and drag over the text below
            </span>
          </div>
          <div className="p-4 space-y-3">
            <div
              ref={containerRef}
              onMouseUp={handleMouseUp}
              data-testid="highlight-container"
              className="font-mono text-sm text-zinc-200 bg-zinc-950 border border-zinc-800 rounded-lg p-3 leading-relaxed select-text whitespace-pre-wrap break-all"
            >
              {highlighted}
            </div>

            {overlapError && (
              <div className="flex items-start gap-2 text-xs text-orange-400 bg-orange-900/20 border border-orange-900/40 rounded-lg p-3">
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{overlapError}</span>
              </div>
            )}

            {spans.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {spans.map((s) => (
                  <button
                    key={s.id}
                    onClick={() => setEditor({ mode: "edit", span: s })}
                    className="flex items-center gap-1 rounded-full bg-zinc-800 hover:bg-zinc-700 px-2 py-0.5 text-xs text-zinc-300 font-mono"
                  >
                    <Tag className="h-3 w-3 text-teal-400" />
                    {s.type === "discard" ? "(ignored)" : s.path}
                    <span className="text-zinc-500">· {SPAN_TYPE_LABELS[s.type]}</span>
                  </button>
                ))}
              </div>
            )}

            {editor && (
              <SpanEditorPanel
                rawLine={rawLine}
                boundary={editor.mode === "new" ? editor.boundary : undefined}
                existingSpan={editor.mode === "edit" ? editor.span : undefined}
                existingPaths={existingPaths}
                onConfirm={confirmSpan}
                onRemove={editor.mode === "edit" ? () => removeSpan(editor.span.id) : undefined}
                onCancel={() => setEditor(null)}
              />
            )}

            {!check && spans.length > 0 && (
              <div className="flex items-start gap-2 text-xs text-zinc-500 bg-zinc-800/40 border border-zinc-800 rounded-lg p-3">
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>
                  No distinguishing prefix was found before your first field — this decoder will attempt to parse
                  every log line. You can add a <code>check:</code> guard by hand after generating, for better
                  discrimination.
                </span>
              </div>
            )}

            {strayWarning && (
              <div className="flex items-start gap-2 text-xs text-orange-400 bg-orange-900/20 border border-orange-900/40 rounded-lg p-3">
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{strayWarning}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {rawLine.trim() && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
          <div className="px-4 py-2.5 border-b border-zinc-800 bg-zinc-900/80">
            <span className="text-xs font-medium text-zinc-400 uppercase tracking-wider">3. Describe this decoder</span>
          </div>
          <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-zinc-500 block mb-1">Title</label>
              <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="My Custom Integration"
                className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 outline-none focus:border-teal-500" />
            </div>
            <div>
              <label className="text-xs text-zinc-500 block mb-1">Author</label>
              <input value={author} onChange={(e) => setAuthor(e.target.value)} placeholder="Your name"
                className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 outline-none focus:border-teal-500" />
            </div>
            <div className="sm:col-span-2">
              <label className="text-xs text-zinc-500 block mb-1">Description</label>
              <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What does this decoder normalize?"
                className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 outline-none focus:border-teal-500" />
            </div>
            <div>
              <label className="text-xs text-zinc-500 block mb-1">Event category</label>
              <select value={category} onChange={(e) => setCategory(e.target.value)}
                className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 outline-none focus:border-teal-500">
                {EVENT_CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
