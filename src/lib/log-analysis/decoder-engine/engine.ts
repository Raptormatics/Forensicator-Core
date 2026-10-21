// ─────────────────────────────────────────────────────────────────────────────
// Decoder Engine — public API
//
// Lifecycle:
//   1. loadDecoders() — called once at startup; loads DB records, compiles YAML
//   2. decodeLogLine(raw) — tries each decoder in priority order
//
// Priority order:
//   1. Custom decoders (is_builtin = false), check-present decoders first
//   2. Built-in decoders (is_builtin = true), check-present decoders first
//   3. No match → returns null
// ─────────────────────────────────────────────────────────────────────────────

import yaml from "js-yaml";

import type { DecoderDef, DecoderYaml, NormalizeBlock, NormalizedLogEntry } from "./types";
import { compilePattern, matchPatterns } from "./patternParser";
import { evaluateCheck }               from "./checkEvaluator";
import { runNormalize }                from "./normalizeRunner";
import { precompileDecoderPatterns }   from "./regex-cache";

// ── In-memory decoder registry ───────────────────────────────────────────

let _decoders: DecoderDef[] = [];
let _loaded = false;

// ── Discriminator index ───────────────────────────────────────────────────
//
// Partitions decoders by format at load time so matchDecoder() never needs to
// walk the full list. For most events the correct decoder is found with zero
// regex evaluations — only O(1) string checks.

interface DiscriminatorIndex {
  json:         DecoderDef[];
  xml:          DecoderDef[];
  fingerprints: { literal: string; decoder: DecoderDef }[];
  prefixes:     { prefix: string;  decoder: DecoderDef }[];
  rest:         DecoderDef[];
}

let _index: DiscriminatorIndex = { json: [], xml: [], fingerprints: [], prefixes: [], rest: [] };

/** Extract literal fingerprints from a check expression string. */
function extractFingerprints(check: string): { contains: string[]; startsWith: string[] } {
  const contains: string[] = [];
  const startsWith: string[] = [];
  // contains($event.original, 'X') or contains($event.original, "X")
  const cRe = /contains\s*\(\s*\$event\.original\s*,\s*['"]([^'"]+)['"]\s*\)/gi;
  let m: RegExpExecArray | null;
  while ((m = cRe.exec(check)) !== null) contains.push(m[1]);
  // starts_with($event.original, 'X')
  const sRe = /starts_with\s*\(\s*\$event\.original\s*,\s*['"]([^'"]+)['"]\s*\)/gi;
  while ((m = sRe.exec(check)) !== null) startsWith.push(m[1]);
  return { contains, startsWith };
}

function buildIndex(decoders: DecoderDef[]): DiscriminatorIndex {
  const idx: DiscriminatorIndex = { json: [], xml: [], fingerprints: [], prefixes: [], rest: [] };

  for (const dec of decoders) {
    if (!dec.check) { idx.rest.push(dec); continue; }

    const check = dec.check;

    // JSON decoders: check uses exists() on JSON fields (no $event.original)
    if (check.includes("exists(") && !check.includes("$event.original")) {
      idx.json.push(dec);
      continue;
    }
    // XML / Windows decoders
    if (check.includes("<Event xmlns") || check.includes("Event xmlns") ||
        check.includes("<Channel>")) {
      idx.xml.push(dec);
      continue;
    }

    // Extract contains / starts_with literals
    const { contains, startsWith } = extractFingerprints(check);
    let indexed = false;
    for (const s of startsWith) {
      idx.prefixes.push({ prefix: s, decoder: dec });
      indexed = true;
    }
    for (const s of contains) {
      idx.fingerprints.push({ literal: s, decoder: dec });
      indexed = true;
    }
    if (!indexed) idx.rest.push(dec);
  }

  return idx;
}

// ── YAML Compilation ─────────────────────────────────────────────────────────

/**
 * Parse and compile a YAML string into a DecoderDef.
 * Throws if the YAML is structurally invalid.
 */
export function compileDecoder(yamlContent: string, isBuiltin = false): DecoderDef {
  const raw = yaml.load(yamlContent) as DecoderYaml;

  if (!raw || typeof raw !== "object") throw new Error("Decoder YAML must be a mapping");
  if (!raw.name || typeof raw.name !== "string") throw new Error("Decoder must have a 'name' field");

  // Pre-compile all regex patterns found in this decoder's YAML
  precompileDecoderPatterns(yamlContent);

  // Collect parse|<field> keys
  const patterns = Object.entries(raw)
    .filter(([k]) => k.startsWith("parse|"))
    .flatMap(([, v]) => {
      const list = Array.isArray(v) ? v : [v];
      return (list as string[]).map((p) => compilePattern(String(p)));
    });

  // Compile normalize blocks
  const normalizeRaw: DecoderYaml["normalize"] = raw.normalize ?? [];
  const normalize: NormalizeBlock[] = (normalizeRaw ?? []).map((block) => {
    const mapEntries = block.map ?? [];
    const mapRecord: Record<string, string> = {};
    for (const entry of mapEntries) {
      for (const [k, v] of Object.entries(entry)) {
        mapRecord[k] = String(v);
      }
    }
    return { check: block.check != null ? String(block.check) : undefined, map: mapRecord };
  });

  return {
    name:       raw.name,
    enabled:    raw.enabled ?? true,
    isBuiltin,
    title:      raw.metadata?.title,
    description:raw.metadata?.description,
    parents:    raw.parents ?? [],
    check:      raw.check != null ? String(raw.check) : undefined,
    priority:   Number.isFinite(Number(raw.priority)) ? Number(raw.priority) : 0,
    patterns,
    normalize,
    yaml:       yamlContent,
  };
}

/** Sort: check-present decoders before check-less (more specific first),
 * then by YAML `priority:` descending. Without the priority step, order
 * fell back to DB insertion order — and since seeding inserts the bundled
 * YAML files alphabetically, the generic windows-event decoder (whose check
 * matches every Windows XML event) was evaluated before windows-powershell/
 * windows-security/windows-sysmon and shadowed all three. Array.sort is
 * stable, so equal-priority decoders keep their existing relative order. */
function sortDecoders(defs: DecoderDef[]): DecoderDef[] {
  return [...defs].sort((a, b) => {
    const aHasCheck = !!a.check;
    const bHasCheck = !!b.check;
    if (aHasCheck && !bHasCheck) return -1;
    if (!aHasCheck && bHasCheck) return  1;
    return (b.priority ?? 0) - (a.priority ?? 0);
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Load and compile all decoders from the database.
 * Custom decoders are loaded first, then built-ins.
 * Call once at app start; re-call after saving a new decoder.
 */
export async function loadDecoders(): Promise<void> {
  try {
    // Dynamic import to avoid circular deps and allow server-side only usage
    const { prisma } = await import("@/lib/db/prisma");
    const rows = await prisma.logDecoder.findMany({
      where: { enabled: true },
      orderBy: [{ isBuiltin: "asc" }, { createdAt: "asc" }],
    });

    const custom:  DecoderDef[] = [];
    const builtin: DecoderDef[] = [];

    for (const row of rows) {
      try {
        const def = compileDecoder(row.yamlContent, row.isBuiltin);
        def.enabled = row.enabled;
        if (row.isBuiltin) builtin.push(def);
        else custom.push(def);
      } catch {
        // Skip malformed decoders silently in production
      }
    }

    _decoders = [...sortDecoders(custom), ...sortDecoders(builtin)];
    _index    = buildIndex(_decoders);
    _loaded = true;
  } catch {
    // DB may not be ready during build — allow graceful degradation
    _decoders = [];
    _loaded = true;
  }
}

/**
 * Register a compiled DecoderDef directly (used for seeding built-ins
 * before the DB is available, and for testing).
 */
export function registerDecoder(def: DecoderDef): void {
  _decoders = _decoders.filter((d) => d.name !== def.name);
  if (def.isBuiltin) {
    _decoders.push(def);
  } else {
    _decoders.unshift(def);
  }
  // Keep the same custom-before-builtin, then check/priority ordering
  // loadDecoders() produces, and rebuild the index matchDecoder() reads —
  // previously a registered decoder was never matched at all.
  _decoders = [...sortDecoders(_decoders.filter((d) => !d.isBuiltin)), ...sortDecoders(_decoders.filter((d) => d.isBuiltin))];
  _index = buildIndex(_decoders);
  _loaded = true;
}

/** Clear all loaded decoders (for testing) */
export function resetDecoders(): void {
  _decoders = [];
  _loaded = false;
}

// ── JSON context helpers ─────────────────────────────────────────────────────

/**
 * If rawLine is valid JSON, parse it and inject all top-level keys into the
 * base context so decoders can reference them directly (no $ prefix required).
 * The parsed object is also stored under __json__ for dotpath resolution.
 */
export function buildBaseContext(rawLine: string): Record<string, unknown> {
  const ctx: Record<string, unknown> = {
    "event.original": rawLine,
    message: rawLine,
  };

  if (rawLine.trimStart().startsWith("{")) {
    try {
      const parsed = JSON.parse(rawLine) as Record<string, unknown>;
      // Store as __json__ only — resolveRef / resolveArg look here for bare names.
      // We do NOT inject keys at top-level to avoid polluting the output.
      ctx["__json__"] = parsed;
    } catch {
      // Not valid JSON — leave context as-is
    }
  }

  return ctx;
}

/**
 * Find the first enabled decoder whose check: passes for this log line.
 * Uses the discriminator index to avoid evaluating all checks.
 */
export function matchDecoder(rawLine: string): DecoderDef | null {
  if (!_loaded) return null;

  const checkCtx = buildBaseContext(rawLine);

  // Determine format from the first character
  const firstChar = rawLine.trimStart().charCodeAt(0);
  const isJson = firstChar === 0x7B; // '{'
  const isXml  = rawLine.startsWith("<Event xmlns");

  // Build a deduplicated candidate list for this event
  const seen = new Set<string>();
  const candidates: DecoderDef[] = [];

  const add = (dec: DecoderDef) => {
    if (dec.enabled && !seen.has(dec.name)) { seen.add(dec.name); candidates.push(dec); }
  };

  if (isJson) {
    for (const d of _index.json) add(d);
  } else if (isXml) {
    for (const d of _index.xml) add(d);
  } else {
    // Prefix matches first (cheapest)
    for (const { prefix, decoder } of _index.prefixes) {
      if (rawLine.startsWith(prefix)) add(decoder);
    }
    // Then fingerprint (contains) matches
    for (const { literal, decoder } of _index.fingerprints) {
      if (rawLine.includes(literal)) add(decoder);
    }
  }

  // Always append rest-bucket decoders as fallback
  for (const d of _index.rest) add(d);

  // Evaluate checks against candidates only
  for (const def of candidates) {
    if (def.check && !evaluateCheck(def.check, checkCtx)) continue;
    return def;
  }
  return null;
}

/**
 * Apply a decoder (and its parents) to a raw log line.
 * Returns a NormalizedLogEntry.
 */
export function applyDecoder(decoder: DecoderDef, rawLine: string): NormalizedLogEntry {
  let ctx: Record<string, unknown> = buildBaseContext(rawLine);

  // Run parent decoders first
  for (const parentName of (decoder.parents ?? [])) {
    const parent = _decoders.find((d) => d.name === parentName);
    if (!parent) continue;

    // Parent parse
    if (parent.patterns.length > 0) {
      const parsed = matchPatterns(parent.patterns, rawLine);
      if (parsed) Object.assign(ctx, parsed);
    }

    // Parent normalize
    if (parent.normalize.length > 0) {
      ctx = runNormalize(parent.normalize, ctx);
    }
  }

  // Child parse
  if (decoder.patterns.length > 0) {
    const parsed = matchPatterns(decoder.patterns, rawLine);
    if (parsed) Object.assign(ctx, parsed);
  }

  // Child normalize
  if (decoder.normalize.length > 0) {
    ctx = runNormalize(decoder.normalize, ctx);
  }

  return ctx as NormalizedLogEntry;
}

/**
 * Convenience: match + apply in one call.
 * Returns null if no decoder matched.
 */
export function decodeLogLine(rawLine: string): NormalizedLogEntry | null {
  const decoder = matchDecoder(rawLine);
  if (!decoder) return null;
  return applyDecoder(decoder, rawLine);
}

/**
 * Re-export for admin use: compile + validate without persisting
 */
export { compilePattern } from "./patternParser";
export { evaluateCheck }  from "./checkEvaluator";
