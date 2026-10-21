// ─────────────────────────────────────────────────────────────────────────────
// Decoder Engine — built-in map functions
//
// All functions receive the current context and return a value to assign to
// the target field. Functions are pure — they don't mutate the context.
//
// Adding a new function: add a handler to FUNCTION_REGISTRY below.
// ─────────────────────────────────────────────────────────────────────────────

import { getRegex } from "./regex-cache";

/**
 * Walk a nested object using a dot-separated path string.
 * Tries progressively longer key segments first so that dot-in-key names
 * (e.g. Zeek's flat "id.orig_h") are matched before descending into nested
 * objects.  Both formats are handled correctly:
 *   {"id.orig_h": "1.2.3.4"}          → walkPath(obj, "id.orig_h") = "1.2.3.4"
 *   {"id": {"orig_h": "1.2.3.4"}}     → walkPath(obj, "id.orig_h") = "1.2.3.4"
 */
function walkPath(obj: unknown, path: string): unknown {
  if (obj == null || typeof obj !== "object") return undefined;
  const parts = path.split(".");
  const record = obj as Record<string, unknown>;

  // Greedy: try the longest possible key first, shortening until we find a match
  for (let keyLen = parts.length; keyLen >= 1; keyLen--) {
    const key = parts.slice(0, keyLen).join(".");
    if (key in record) {
      // Exact match — consumed the full path
      if (keyLen === parts.length) return record[key];
      // Partial match — recurse into the value with the remaining path
      return walkPath(record[key], parts.slice(keyLen).join("."));
    }
  }
  return undefined;
}

/**
 * Resolve a field reference against the context.
 * Fast path for `event.original.*`: uses ctx["__json__"] directly instead of
 * re-parsing the raw string on every access.
 */
function resolveArg(arg: unknown, ctx: Record<string, unknown>): unknown {
  if (arg === null || arg === undefined) return undefined;
  // Non-string YAML literals (numbers, booleans) are returned as-is
  if (typeof arg !== "string") return arg;
  // Defensive coercion — guards against any runtime type mismatch
  const t = String(arg ?? "").trim();

  // $field reference
  if (t.startsWith("$")) {
    const key = t.slice(1);
    if (key in ctx) return ctx[key];

    // Fast path: $event.original.* → walk __json__
    if (key.startsWith("event.original.") && ctx["__json__"]) {
      const sub = key.slice("event.original.".length);
      return walkPath(ctx["__json__"], sub);
    }

    // Check __json__ top-level for bare JSON field names
    const json = ctx["__json__"];
    if (json && typeof json === "object") {
      const jsonObj = json as Record<string, unknown>;
      if (key in jsonObj) return jsonObj[key];
    }

    // Progressive prefix match — find the longest ctx key that is a prefix
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

    // Walk ctx itself as a nested object
    let cur: unknown = ctx;
    for (const p of parts) {
      if (cur == null || typeof cur !== "object") return undefined;
      cur = (cur as Record<string, unknown>)[p];
    }
    return cur;
  }

  // Quoted string literal
  if ((t.startsWith("'") && t.endsWith("'")) || (t.startsWith('"') && t.endsWith('"'))) {
    return t.slice(1, -1);
  }

  // Numeric literal
  if (/^[0-9]+([.][0-9]+)?$/.test(t)) {
    return t.includes(".") ? parseFloat(t) : parseInt(t, 10);
  }

  // Bare dotpath: event.original.src_ip  or  id.orig_h  etc.
  if (t.includes(".")) {
    // Fast path: event.original.* → always resolve via __json__, never fall through to literal
    if (t.startsWith("event.original.")) {
      if (ctx["__json__"]) {
        const sub = t.slice("event.original.".length);
        return walkPath(ctx["__json__"], sub);
      }
      return undefined;
    }

    // Progressive prefix match
    const parts = t.split(".");
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
    if (t in ctx) return ctx[t];
  }

  // Bare word — ctx lookup then __json__
  if (t in ctx) return ctx[t];
  {
    const json = ctx["__json__"];
    if (json && typeof json === "object") {
      const jsonObj = json as Record<string, unknown>;
      if (t in jsonObj) return jsonObj[t];
    }
  }

  // Return as literal string (e.g. plain-string map values: event.kind: event)
  return t;
}

function toStr(v: unknown): string {
  return v == null ? "" : String(v);
}

/** Parse a simple argument list, respecting nested parentheses */
export function parseArgList(raw: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let current = "";

  for (const ch of raw) {
    if (ch === "(" ) depth++;
    else if (ch === ")") depth--;
    else if (ch === "," && depth === 0) {
      args.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) args.push(current.trim());
  return args;
}

// ── Function registry ─────────────────────────────────────────────────────────

type FnHandler = (args: string[], ctx: Record<string, unknown>) => unknown;

const FUNCTION_REGISTRY: Record<string, FnHandler> = {

  /** append a value to an array field */
  array_append(args, ctx) {
    const value = resolveArg(args[0] ?? "", ctx);
    // The current field value (caller will use target to read existing)
    return { __fn: "array_append", value };
  },

  /** append only if not already present */
  array_append_unique(args, ctx) {
    const value = resolveArg(args[0] ?? "", ctx);
    return { __fn: "array_append_unique", value };
  },

  /** extract first capture group from a regex — pattern compiled once */
  regex_extract(args, ctx) {
    const source  = toStr(resolveArg(args[0] ?? "", ctx));
    const pattern = toStr(resolveArg(args[1] ?? "", ctx));
    try {
      const m = getRegex(pattern).exec(source);
      return m?.[1] ?? undefined;
    } catch {
      return undefined;
    }
  },

  /** parse key=value pairs into an object */
  parse_key_value(args, ctx) {
    const source  = toStr(resolveArg(args[0] ?? "", ctx));
    const kvSep   = toStr(resolveArg(args[1] ?? "=", ctx));
    const pairSep = toStr(resolveArg(args[2] ?? " ", ctx));

    const result: Record<string, string> = {};
    // Whitespace-separated pairs must not split inside a quoted value —
    // FortiGate/most firewalls write policyname="Implicit Deny".
    const pairs = pairSep === " "
      ? source.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) ?? []
      : source.split(pairSep);
    for (const pair of pairs) {
      const idx = pair.indexOf(kvSep);
      if (idx === -1) continue;
      const k = pair.slice(0, idx).trim();
      let v = pair.slice(idx + kvSep.length).trim();
      // Strip surrounding quotes from values
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      if (k) result[k] = v;
    }
    return result;
  },

  /** look up a key in a parsed KV object */
  get_key_in(args, ctx) {
    const obj = resolveArg(args[0] ?? "", ctx);
    const key = toStr(resolveArg(args[1] ?? "", ctx));
    if (obj == null || typeof obj !== "object") return undefined;
    return (obj as Record<string, unknown>)[key];
  },

  /** parse a JSON string into an object and store it in context */
  parse_json(args, ctx) {
    const source = toStr(resolveArg(args[0] ?? "", ctx));
    try {
      return JSON.parse(source);
    } catch {
      return undefined;
    }
  },

  /**
   * Extract a field from a JSON string or already-parsed object.
   * Usage: get_json_field($json_string, 'fieldname')
   *        get_json_field($_parsed_obj, 'fieldname')
   */
  get_json_field(args, ctx) {
    const source = resolveArg(args[0] ?? "", ctx);
    const key    = toStr(resolveArg(args[1] ?? "", ctx));
    if (source == null) return undefined;
    if (typeof source === "object") {
      return (source as Record<string, unknown>)[key];
    }
    if (typeof source === "string") {
      try {
        const parsed = JSON.parse(source) as Record<string, unknown>;
        return parsed[key];
      } catch {
        return undefined;
      }
    }
    return undefined;
  },

  /** cast to integer */
  parse_long(args, ctx) {
    const v = resolveArg(args[0] ?? "", ctx);
    const n = parseInt(toStr(v), 10);
    return isNaN(n) ? undefined : n;
  },

  /** cast to float */
  parse_double(args, ctx) {
    const v = resolveArg(args[0] ?? "", ctx);
    const n = parseFloat(toStr(v));
    return isNaN(n) ? undefined : n;
  },

  /** lowercase */
  downcase(args, ctx) {
    return toStr(resolveArg(args[0] ?? "", ctx)).toLowerCase();
  },

  /** concatenate two values with a separator */
  concat(args, ctx) {
    const a   = toStr(resolveArg(args[0] ?? "", ctx));
    const sep = toStr(resolveArg(args[1] ?? "", ctx));
    const b   = toStr(resolveArg(args[2] ?? "", ctx));
    return a + sep + b;
  },

  /** signal deletion of the target field */
  delete() {
    return { __fn: "delete" };
  },
};

/** Nested function call: outer(inner(...)) — resolve inner first */
function resolveNestedCall(expr: string, ctx: Record<string, unknown>): unknown {
  // Match outer_fn(inner_fn(args...), ...)
  const outerMatch = expr.match(/^([a-z_]+)\((.+)\)$/);
  if (!outerMatch) return resolveArg(expr, ctx);

  const fnName = outerMatch[1];
  const innerExpr = outerMatch[2];

  // Check for nested call as first argument
  const innerCallMatch = innerExpr.match(/^([a-z_]+)\((.+)\)$/);
  if (innerCallMatch) {
    const innerResult = resolveNestedCall(innerExpr, ctx);
    const tempKey = "__nested_result__";
    const tempCtx = { ...ctx, [tempKey]: innerResult };
    // Replace first arg with temp key ref
    const handler = FUNCTION_REGISTRY[fnName];
    if (!handler) return innerResult;
    // Call outer with inner result as $__nested_result__
    return handler([`$${tempKey}`, ...parseArgList(innerExpr).slice(1)], tempCtx);
  }

  const handler = FUNCTION_REGISTRY[fnName];
  if (!handler) return resolveArg(innerExpr, ctx);
  return handler(parseArgList(innerExpr), ctx);
}

/**
 * Resolve a map value expression.
 * Handles: literals, $field refs, function calls, nested function calls.
 */
export function resolveExpression(
  expression: unknown,
  ctx: Record<string, unknown>,
  targetField: string
): unknown {
  // YAML values can be numbers, booleans or null — coerce to string so the
  // rest of the resolver can treat everything uniformly.
  if (expression === null || expression === undefined) return undefined;
  if (typeof expression !== "string") return expression;
  // Defensive coercion — guards against any runtime type mismatch
  const expr = String(expression ?? "").trim();

  // Function call: name(args)
  const fnMatch = expr.match(/^([a-z_]+)\(([^)]*(?:\([^)]*\)[^)]*)*)\)$/);
  if (fnMatch) {
    const fnName = fnMatch[1];
    const rawArgs = fnMatch[2] ?? "";

    // Handle nested calls by checking if any arg is itself a function call
    const args = parseArgList(rawArgs);

    // Resolve nested function calls in args
    const tempKeys: string[] = [];
    const resolvedArgs = args.map((arg) => {
      const nestedFn = arg.match(/^([a-z_]+)\(/);
      if (nestedFn) {
        const result = resolveNestedCall(arg, ctx);
        // Store in a temp key so the outer handler can resolve it via $ref
        const key = "__arg_" + nestedFn[1] + "__";
        ctx[key] = result;
        tempKeys.push(key);
        return `$${key}`;
      }
      return arg;
    });

    const handler = FUNCTION_REGISTRY[fnName];
    if (!handler) {
      for (const k of tempKeys) delete ctx[k];
      return resolveArg(expr, ctx);
    }
    const fnResult = handler(resolvedArgs, ctx);
    // Clean up temp args — they must not appear in the final output
    for (const k of tempKeys) delete ctx[k];
    return fnResult;
  }

  // $field reference or literal
  return resolveArg(expr, ctx);
}

/** Apply a resolved value to the target field in the context */
export function applyValue(
  ctx: Record<string, unknown>,
  targetField: string,
  resolved: unknown
): void {
  if (resolved == null) return;

  // Special function results
  if (typeof resolved === "object" && resolved !== null && "__fn" in resolved) {
    const fn = (resolved as { __fn: string; value?: unknown }).__fn;

    if (fn === "delete") {
      delete ctx[targetField];
      return;
    }

    if (fn === "array_append" || fn === "array_append_unique") {
      const val = (resolved as Record<string, unknown>)["value"];
      if (val === undefined || val === null) return;

      const existing = ctx[targetField];
      if (!Array.isArray(existing)) {
        ctx[targetField] = [val];
      } else if (fn === "array_append") {
        existing.push(val);
      } else if (!existing.includes(val)) {
        existing.push(val);
      }
      return;
    }
  }

  ctx[targetField] = resolved;
}
