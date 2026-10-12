// ─────────────────────────────────────────────────────────────────────────────
// Visual decoder builder — reverse-parse an existing decoder's YAML back
// into a sample line + spans, so the visual editor can be used on an
// already-saved decoder, not just for creating a new one.
//
// Decoders don't store the sample line they were originally built from, so
// this asks the caller for one and reconstructs spans by actually matching
// the decoder's own compiled pattern against it (using the regex's 'd' flag
// match indices) — a real round-trip through the same engine code the
// decoder runs on, not a separate reimplementation of the pattern syntax.
// ─────────────────────────────────────────────────────────────────────────────

import yaml from "js-yaml";
import { compilePattern } from "@/lib/log-analysis/decoder-engine/patternParser";
import type { ParsedField } from "@/lib/log-analysis/decoder-engine/types";
import type { Span, SpanType, DecoderMeta } from "./patternBuilder";
import { EVENT_CATEGORIES, genId } from "./patternBuilder";

export interface ReverseParseResult {
  rawLine: string;
  spans: Span[];
  meta: DecoderMeta;
  name: string;
}

export type ReverseParseError =
  | { reason: "no-pattern" }
  | { reason: "multi-pattern" }
  | { reason: "yaml-error"; detail: string }
  | { reason: "no-match" };

function fieldTypeToSpanType(field: ParsedField): SpanType {
  switch (field.type) {
    case "quoted-double":
    case "quoted-single": return "quoted";
    case "long":     return "long";
    case "double":   return "double";
    case "between":  return "between";
    case "ISO8601":  return "ISO8601";
    case "SYSLOG":   return "SYSLOG";
    case "optional": return "optional";
    default:         return "string";
  }
}

/**
 * Parses just enough of the YAML to get at parse|event.original and a few
 * metadata fields — deliberately not going through compileDecoder(), since
 * that also validates normalize:/check: in ways irrelevant here and this
 * only needs the raw structure.
 */
function extractYamlParts(yamlContent: string): {
  name: string;
  patterns: string[];
  title: string;
  author: string;
  description: string;
  category: string;
} {
  const raw = yaml.load(yamlContent) as Record<string, unknown>;
  const parseKey = Object.keys(raw ?? {}).find((k) => k.startsWith("parse|"));
  const rawPatterns = parseKey ? raw[parseKey] : undefined;
  const patterns = Array.isArray(rawPatterns) ? rawPatterns.map(String) : rawPatterns ? [String(rawPatterns)] : [];

  const metadata = (raw?.metadata ?? {}) as Record<string, unknown>;
  const normalize = Array.isArray(raw?.normalize) ? (raw.normalize as Array<{ map?: Array<Record<string, unknown>> }>) : [];
  let category = EVENT_CATEGORIES[0] as string;
  for (const block of normalize) {
    for (const entry of block.map ?? []) {
      const catExpr = entry["event.category"];
      if (typeof catExpr === "string") {
        const m = catExpr.match(/array_append\((\w+)\)/);
        if (m) category = m[1];
      }
    }
  }

  return {
    name: typeof raw?.name === "string" ? raw.name : "",
    patterns,
    title: typeof metadata.title === "string" ? metadata.title : "",
    author: typeof metadata.author === "string" ? metadata.author : "",
    description: typeof metadata.description === "string" ? metadata.description : "",
    category,
  };
}

/** Cheap upfront check — no sample line needed — for whether visual editing could ever work for this YAML. */
export function canReverseParse(yamlContent: string): { ok: true } | { ok: false; reason: "no-pattern" | "multi-pattern" | "yaml-error" } {
  let parts: ReturnType<typeof extractYamlParts>;
  try {
    parts = extractYamlParts(yamlContent);
  } catch {
    return { ok: false, reason: "yaml-error" };
  }
  if (parts.patterns.length === 0) return { ok: false, reason: "no-pattern" };
  if (parts.patterns.length > 1) return { ok: false, reason: "multi-pattern" };
  return { ok: true };
}

export function reverseParseDecoder(yamlContent: string, rawLine: string): ReverseParseResult | ReverseParseError {
  let parts: ReturnType<typeof extractYamlParts>;
  try {
    parts = extractYamlParts(yamlContent);
  } catch (e) {
    return { reason: "yaml-error", detail: String(e) };
  }

  if (parts.patterns.length === 0) return { reason: "no-pattern" };
  if (parts.patterns.length > 1) return { reason: "multi-pattern" };

  let compiled;
  try {
    compiled = compilePattern(parts.patterns[0]);
  } catch (e) {
    return { reason: "yaml-error", detail: String(e) };
  }

  const match = compiled.regex.exec(rawLine) as (RegExpExecArray & { indices?: { groups?: Record<string, [number, number]> } }) | null;
  if (!match || !match.indices?.groups) return { reason: "no-match" };

  const spans: Span[] = [];
  for (const field of compiled.fields) {
    const range = match.indices.groups[field.groupName];
    if (!range) continue;
    const [start, end] = range;
    if (start === end) continue; // empty optional capture — nothing to highlight

    const type = fieldTypeToSpanType(field);
    const span: Span = { id: genId(), start, end, path: field.path, type };
    if (type === "quoted") {
      span.quoteChar = field.type === "quoted-single" ? "'" : '"';
      // The quote chars are consumed by the token itself in the real match,
      // but the field's own captured range is the INNER text only — extend
      // by one char each side so this round-trips through the same
      // consumedBoundary display/logic a freshly-drawn selection would use.
      span.start = start - 1;
      span.end = end + 1;
      span.consumedBoundary = true;
    } else if (type === "between" && field.between) {
      span.between = field.between;
      span.start = start - field.between.open.length;
      span.end = end + field.between.close.length;
      span.consumedBoundary = true;
    }
    spans.push(span);
  }

  return {
    rawLine,
    spans,
    meta: { title: parts.title, author: parts.author, description: parts.description, category: parts.category },
    name: parts.name,
  };
}
