// ─────────────────────────────────────────────────────────────────────────────
// Check Evaluator — evaluates check: expression strings against a field context
// ─────────────────────────────────────────────────────────────────────────────

import { getRegex } from "./regex-cache";

/** Walk a nested object/array using a dot-separated path. */
function walkPath(obj: unknown, path: string): unknown {
  let cur = obj;
  for (const key of path.split(".")) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}

/**
 * Resolve a $field reference from the context map.
 * Fast path for event.original.* → uses ctx["__json__"] directly.
 */
function resolveRef(ref: string, ctx: Record<string, unknown>): unknown {
  const key = ref.startsWith("$") ? ref.slice(1) : ref;

  // Direct flat key
  if (key in ctx) return ctx[key];

  // Fast path: event.original.* → walk __json__
  if (key.startsWith("event.original.") && ctx["__json__"]) {
    return walkPath(ctx["__json__"], key.slice("event.original.".length));
  }

  // __json__ top-level for bare field names
  const json = ctx["__json__"];
  if (json && typeof json === "object") {
    const jsonObj = json as Record<string, unknown>;
    if (key in jsonObj) return jsonObj[key];
  }

  // Progressive prefix match
  const parts = key.split(".");
  for (let i = parts.length - 1; i >= 1; i--) {
    const prefix = parts.slice(0, i).join(".");
    const rest   = parts.slice(i).join(".");
    const base   = ctx[prefix];
    if (base === undefined || base === null) continue;
    if (typeof base === "string" && base.trimStart().startsWith("{")) {
      try {
        const parsed = JSON.parse(base) as Record<string, unknown>;
        const v = walkPath(parsed, rest);
        if (v !== undefined) return v;
      } catch { /* not JSON */ }
    }
    if (typeof base === "object") {
      const v = walkPath(base, rest);
      if (v !== undefined) return v;
    }
  }

  // Walk ctx as nested object
  let cur: unknown = ctx;
  for (const p of parts) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

function getString(ref: string, ctx: Record<string, unknown>): string {
  const v = resolveRef(ref, ctx);
  return v == null ? "" : String(v);
}

/** Unquote a single- or double-quoted string literal */
function unquote(s: string): string {
  const t = s.trim();
  if ((t.startsWith("'") && t.endsWith("'")) || (t.startsWith('"') && t.endsWith('"'))) {
    return t.slice(1, -1);
  }
  return t;
}

/** Evaluate one atomic predicate */
function evaluateAtom(atom: string, ctx: Record<string, unknown>): boolean {
  atom = atom.trim();

  // Field ref pattern: optional $ followed by word chars and dots
  // Accepts both $source.ip and source.ip and _tmp_json.field
  const FREF = String.raw`(\$?[\w._]+)`;

  // starts_with($field, 'prefix') or starts_with(field, 'prefix')
  const swMatch = atom.match(new RegExp(`^starts_with\\(\\s*${FREF}\\s*,\\s*(.+)\\)$`));
  if (swMatch) {
    const haystack = getString(swMatch[1], ctx);
    return haystack.startsWith(unquote(swMatch[2]));
  }

  // contains($field, 'substr')
  const conMatch = atom.match(new RegExp(`^contains\\(\\s*${FREF}\\s*,\\s*(.+)\\)$`));
  if (conMatch) {
    const haystack = getString(conMatch[1], ctx);
    return haystack.includes(unquote(conMatch[2]));
  }

  // string_equal($field, 'value') — also handles double-quoted values
  const seMatch = atom.match(new RegExp(`^string_equal\\(\\s*${FREF}\\s*,\\s*(.+)\\)$`));
  if (seMatch) {
    const lhs = getString(seMatch[1], ctx);
    return lhs === unquote(seMatch[2]);
  }

  // regex_match($field, 'pattern') — pre-compiled via regex cache
  const rmMatch = atom.match(new RegExp(`^regex_match\\(\\s*${FREF}\\s*,\\s*['"](.+?)['"]\\)$`));
  if (rmMatch) {
    const haystack = getString(rmMatch[1], ctx);
    try {
      return getRegex(rmMatch[2]).test(haystack);
    } catch {
      return false;
    }
  }

  // exists($field) or exists(bareField)
  const exMatch = atom.match(new RegExp(`^exists\\(\\s*${FREF}\\s*\\)$`));
  if (exMatch) {
    const v = resolveRef(exMatch[1], ctx);
    return v !== undefined && v !== null && v !== "";
  }

  // not_exists($field) or not_exists(bareField)
  const nexMatch = atom.match(new RegExp(`^not_exists\\(\\s*${FREF}\\s*\\)$`));
  if (nexMatch) {
    const v = resolveRef(nexMatch[1], ctx);
    return v === undefined || v === null || v === "";
  }

  // $field == value  or  bareField == value
  const eqMatch = atom.match(new RegExp(`^${FREF}\\s*==\\s*(.+)$`));
  if (eqMatch) {
    const lhs = getString(eqMatch[1], ctx);
    return lhs === unquote(eqMatch[2]);
  }

  // $field != value  or  bareField != value
  const neMatch = atom.match(new RegExp(`^${FREF}\\s*!=\\s*(.+)$`));
  if (neMatch) {
    const lhs = getString(neMatch[1], ctx);
    return lhs !== unquote(neMatch[2]);
  }

  // $field > value (numeric)
  const gtMatch = atom.match(new RegExp(`^${FREF}\\s*>\\s*(.+)$`));
  if (gtMatch) {
    const lhs = parseFloat(getString(gtMatch[1], ctx));
    return lhs > parseFloat(gtMatch[2].trim());
  }

  // $field < value (numeric)
  const ltMatch = atom.match(new RegExp(`^${FREF}\\s*<\\s*(.+)$`));
  if (ltMatch) {
    const lhs = parseFloat(getString(ltMatch[1], ctx));
    return lhs < parseFloat(ltMatch[2].trim());
  }

  // key: string_equal("value") — Wazuh-style field check shorthand
  // e.g.  _tmp_json.event.action: string_equal("netflow_flow")
  const wazuhMatch = atom.match(/^([\w._]+)\s*:\s*string_equal\(["'](.+?)["']\)$/);
  if (wazuhMatch) {
    const lhs = getString(wazuhMatch[1], ctx);
    return lhs === wazuhMatch[2];
  }

  // Unknown atom — fail open (don't block processing)
  return true;
}

/**
 * Split expression on top-level AND / OR tokens (case-insensitive).
 * Does NOT split on AND/OR inside function parentheses.
 */
function splitTopLevel(expr: string, op: "AND" | "OR"): string[] {
  const results: string[] = [];
  let depth = 0;
  let current = "";
  const re = new RegExp(`\\b${op}\\b`, "gi");

  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (ch === "(") depth++;
    else if (ch === ")") depth--;

    if (depth === 0) {
      // Check if we hit the operator keyword
      const sub = expr.slice(i);
      const m = sub.match(new RegExp(`^${op}\\b`, "i"));
      if (m) {
        results.push(current.trim());
        current = "";
        i += m[0].length - 1;
        continue;
      }
    }
    current += ch;
  }
  if (current.trim()) results.push(current.trim());
  return results;
}

/**
 * Evaluate a check: expression string against a context map.
 * Supports AND / OR with short-circuit evaluation.
 */
export function evaluateCheck(expression: unknown, ctx: Record<string, unknown>): boolean {
  // Defensive guard — YAML may produce non-string values for 'check' fields
  if (expression === null || expression === undefined) return true;
  if (typeof expression !== "string") return true;
  const expr = String(expression ?? "").trim();
  if (!expr) return true;

  // Try splitting on OR first (lower precedence)
  const orParts = splitTopLevel(expr, "OR");
  if (orParts.length > 1) {
    return orParts.some((part) => evaluateCheck(part.trim(), ctx));
  }

  // Split on AND
  const andParts = splitTopLevel(expr, "AND");
  if (andParts.length > 1) {
    return andParts.every((part) => evaluateCheck(part.trim(), ctx));
  }

  // Single atom
  return evaluateAtom(expr, ctx);
}
