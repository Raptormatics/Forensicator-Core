/**
 * Sigma rule compiler: one SigmaHQ YAML rule -> a JSON-serializable
 * CompiledSigmaRule that src/lib/sigma/engine.ts evaluates against log
 * events. Covers the Sigma 2.0 detection syntax SigmaHQ's rule packages use:
 *
 *   - selections as maps (AND of fields), lists of maps (OR), or keyword lists
 *   - value modifiers: contains, startswith, endswith, all, re (+ i/m/s),
 *     windash, cidr, base64, base64offset, utf16le/utf16be/utf16/wide,
 *     exists, gt/gte/lt/lte, fieldref, cased
 *   - wildcards (* and ?, with \ escapes) in plain values
 *   - conditions with and/or/not, parentheses, "1 of"/"all of" a selection
 *     or a pattern (selection_*), and "them"
 *
 * Anything else — correlation rules, aggregation conditions ("| count()"),
 * placeholders (expand), an unknown modifier — compiles to
 * { supported: false, reason } so the rule is listed but never run.
 */
import yaml from "js-yaml";

export type SigmaLevel = "informational" | "low" | "medium" | "high" | "critical";

/** One value test. Strings are pre-lowercased unless `cased`. */
export type ValueTest =
  | { t: "eq" | "contains" | "startswith" | "endswith"; s: string; cased?: boolean }
  | { t: "re"; re: string; flags: string }
  | { t: "cidr"; cidr: string }
  | { t: "num"; op: "gt" | "gte" | "lt" | "lte"; n: number }
  | { t: "exists"; v: boolean }
  | { t: "null" }
  | { t: "fieldref"; field: string; cased?: boolean };

/** One "Field|modifiers: values" entry: any value matches (or all, with |all). */
export type FieldTest = { field: string; tests: ValueTest[]; all: boolean };

export type Selection =
  | { k: "map"; alternatives: FieldTest[][] }   // OR of (AND of field tests)
  | { k: "keywords"; tests: ValueTest[]; all: boolean };

export type Cond =
  | { op: "and" | "or"; args: Cond[] }
  | { op: "not"; arg: Cond }
  | { op: "sel"; name: string }
  | { op: "of"; quant: "1" | "all"; names: string[] };

export type CompiledSigmaRule = { selections: Record<string, Selection>; conditions: Cond[] };

export type SigmaRuleMeta = {
  sigmaId: string;
  title: string;
  description: string | null;
  status: string | null;
  level: SigmaLevel;
  author: string | null;
  tags: string[];
  references: string[];
  falsePositives: string[];
  product: string | null;
  category: string | null;
  service: string | null;
};

export type CompileResult =
  | { ok: true; meta: SigmaRuleMeta; compiled: CompiledSigmaRule }
  | { ok: false; meta: SigmaRuleMeta | null; reason: string };

class Unsupported extends Error {}

const LEVELS: SigmaLevel[] = ["informational", "low", "medium", "high", "critical"];

function strList(v: unknown): string[] {
  if (v == null) return [];
  return (Array.isArray(v) ? v : [v]).map((x) => String(x)).filter(Boolean);
}

function meta(doc: Record<string, unknown>): SigmaRuleMeta {
  const ls = (doc.logsource ?? {}) as Record<string, unknown>;
  const level = String(doc.level ?? "medium").toLowerCase() as SigmaLevel;
  const s = (v: unknown) => (v == null || v === "" ? null : String(v));
  return {
    sigmaId: String(doc.id ?? ""),
    title: String(doc.title ?? "(untitled Sigma rule)"),
    description: s(doc.description),
    status: s(doc.status),
    level: LEVELS.includes(level) ? level : "medium",
    author: s(doc.author),
    tags: strList(doc.tags),
    references: strList(doc.references),
    falsePositives: strList(doc.falsepositives),
    product: s(ls.product)?.toLowerCase() ?? null,
    category: s(ls.category)?.toLowerCase() ?? null,
    service: s(ls.service)?.toLowerCase() ?? null,
  };
}

// ── Values ──────────────────────────────────────────────────────────────

const RE_SPECIAL = /[.*+?^${}()|[\]\\/]/g;

/** Sigma wildcard string -> { literal } when it has no live wildcard, else a regex body. */
function wildcard(value: string): { literal: string } | { regex: string } {
  let out = "", lit = "", wild = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === "\\" && i + 1 < value.length && "*?\\".includes(value[i + 1])) {
      const n = value[++i];
      out += n.replace(RE_SPECIAL, "\\$&");
      lit += n;
    } else if (c === "*") { out += "[\\s\\S]*"; wild = true; }
    else if (c === "?") { out += "[\\s\\S]"; wild = true; }
    else { out += c.replace(RE_SPECIAL, "\\$&"); lit += c; }
  }
  return wild ? { regex: out } : { literal: lit };
}

function stringTest(value: string, mode: "eq" | "contains" | "startswith" | "endswith", cased: boolean): ValueTest {
  const w = wildcard(value);
  if ("literal" in w) return { t: mode, s: cased ? w.literal : w.literal.toLowerCase(), ...(cased ? { cased } : {}) };
  const body = mode === "contains" ? `[\\s\\S]*${w.regex}[\\s\\S]*` : mode === "startswith" ? `${w.regex}[\\s\\S]*` : mode === "endswith" ? `[\\s\\S]*${w.regex}` : w.regex;
  return { t: "re", re: `^${body}$`, flags: cased ? "" : "i" };
}

function encode(value: string, enc: "utf16le" | "utf16be" | null): Buffer {
  if (enc === "utf16le") return Buffer.from(value, "utf16le");
  if (enc === "utf16be") return Buffer.from(Buffer.from(value, "utf16le").swap16());
  return Buffer.from(value, "utf8");
}

/** pySigma's base64offset: the three encodings of the value at byte offsets 0, 1, 2. */
function base64Offsets(raw: Buffer): string[] {
  const starts = [0, 2, 3];
  const ends = [0, -3, -2];
  const out: string[] = [];
  for (let i = 0; i < 3; i++) {
    const b64 = Buffer.concat([Buffer.alloc(i, " "), raw]).toString("base64");
    const end = ends[(raw.length + i) % 3];
    out.push(b64.slice(starts[i], end === 0 ? undefined : end));
  }
  return out;
}

const WINDASH = ["-", "/", "–", "—", "―"];

function windash(value: string): string[] {
  if (!/(^|\s)-/.test(value)) return [value];
  return WINDASH.map((d) => value.replace(/(^|\s)-/g, `$1${d}`));
}

function pythonRegex(src: string, flags: Set<string>): { re: string; flags: string } {
  let re = src;
  const lead = re.match(/^\(\?([imsx]+)\)/);
  if (lead) {
    for (const f of lead[1]) flags.add(f);
    re = re.slice(lead[0].length);
  }
  if (flags.has("x")) throw new Unsupported("regex verbose flag");
  re = re.replace(/\(\?P<(\w+)>/g, "(?<$1>").replace(/\(\?P=(\w+)\)/g, "\\k<$1>").replace(/\\Z/g, "$").replace(/\\A/g, "^");
  const f = [...flags].filter((x) => "ims".includes(x)).join("");
  try { new RegExp(re, f); } catch (e) { throw new Unsupported(`regex not valid in JavaScript: ${(e as Error).message}`); }
  return { re, flags: f };
}

function compileValues(modifiers: string[], raw: unknown, forKeywords: boolean): { tests: ValueTest[]; all: boolean } {
  const mods = modifiers.map((m) => m.toLowerCase());
  const values = Array.isArray(raw) ? raw : [raw];
  const all = mods.includes("all");
  const cased = mods.includes("cased");
  const known = new Set(["contains", "startswith", "endswith", "all", "re", "i", "m", "s", "windash", "cidr", "base64", "base64offset",
    "utf16le", "utf16be", "utf16", "wide", "exists", "gt", "gte", "lt", "lte", "fieldref", "cased"]);
  for (const m of mods) if (!known.has(m)) throw new Unsupported(`modifier |${m}`);

  const tests: ValueTest[] = [];
  for (const v of values) {
    if (v === null || v === undefined) {
      tests.push({ t: "null" });
      continue;
    }
    if (mods.includes("exists")) { tests.push({ t: "exists", v: v === true || String(v).toLowerCase() === "true" }); continue; }
    const num = (["gt", "gte", "lt", "lte"] as const).find((o) => mods.includes(o));
    if (num) {
      const n = Number(v);
      if (Number.isNaN(n)) throw new Unsupported(`non-numeric value for |${num}`);
      tests.push({ t: "num", op: num, n });
      continue;
    }
    if (typeof v === "object") throw new Unsupported("nested value");
    const s = String(v);
    if (/%[A-Za-z_]+%/.test(s) && mods.includes("expand")) throw new Unsupported("placeholder");
    if (mods.includes("fieldref")) { tests.push({ t: "fieldref", field: s, ...(cased ? { cased } : {}) }); continue; }
    if (mods.includes("cidr")) { tests.push({ t: "cidr", cidr: s }); continue; }
    if (mods.includes("re")) {
      const flags = new Set<string>(mods.filter((m) => m === "i" || m === "m" || m === "s"));
      tests.push({ t: "re", ...pythonRegex(s, flags) });
      continue;
    }
    const enc = mods.includes("utf16le") || mods.includes("wide") || mods.includes("utf16") ? "utf16le" : mods.includes("utf16be") ? "utf16be" : null;
    let variants: string[] = mods.includes("windash") ? windash(s) : [s];
    let mode: "eq" | "contains" | "startswith" | "endswith" = mods.includes("contains") ? "contains" : mods.includes("startswith") ? "startswith" : mods.includes("endswith") ? "endswith" : "eq";
    if (mods.includes("base64offset")) {
      variants = variants.flatMap((x) => base64Offsets(encode(x, enc)));
      mode = "contains";
      // base64 text never needs case folding: keep it exact.
      for (const x of variants) tests.push({ t: "contains", s: x, cased: true });
      continue;
    }
    if (mods.includes("base64")) {
      for (const x of variants) tests.push({ t: mode, s: encode(x, enc).toString("base64"), cased: true });
      continue;
    }
    if (forKeywords && mode === "eq") mode = "contains"; // keywords are substring searches
    for (const x of variants) tests.push(stringTest(x, mode, cased));
  }
  return { tests, all };
}

// ── Selections ──────────────────────────────────────────────────────────

function compileMap(map: Record<string, unknown>): FieldTest[] {
  return Object.entries(map).map(([key, value]) => {
    const [field, ...mods] = key.split("|");
    if (!field) throw new Unsupported("keyword map entry");
    const { tests, all } = compileValues(mods, value, false);
    return { field, tests, all };
  });
}

function compileSelection(value: unknown): Selection {
  if (Array.isArray(value)) {
    if (value.length > 0 && value.every((x) => x && typeof x === "object" && !Array.isArray(x))) {
      return { k: "map", alternatives: value.map((m) => compileMap(m as Record<string, unknown>)) };
    }
    if (value.some((x) => x && typeof x === "object")) throw new Unsupported("mixed selection list");
    return { k: "keywords", ...compileValues([], value, true) };
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    // "|all" / "|contains" keys without a field name are keyword selections.
    if (entries.length === 1 && entries[0][0].startsWith("|")) {
      return { k: "keywords", ...compileValues(entries[0][0].split("|").filter(Boolean), entries[0][1], true) };
    }
    return { k: "map", alternatives: [compileMap(value as Record<string, unknown>)] };
  }
  if (typeof value === "string" || typeof value === "number") return { k: "keywords", ...compileValues([], [value], true) };
  throw new Unsupported("empty selection");
}

// ── Conditions ──────────────────────────────────────────────────────────

function globToRegex(pattern: string): RegExp {
  return new RegExp(`^${pattern.replace(RE_SPECIAL, (c) => (c === "*" ? ".*" : `\\${c}`))}$`);
}

export function parseCondition(text: string, selections: string[]): Cond {
  if (/\|/.test(text)) throw new Unsupported("aggregation condition");
  const tokens = text.match(/\(|\)|\b(?:1|all|any) of\b|[^\s()]+/gi) ?? [];
  let pos = 0;
  const peek = () => tokens[pos]?.toLowerCase();
  const expand = (pat: string): string[] => {
    if (pat.toLowerCase() === "them") return [...selections];
    const rx = globToRegex(pat);
    const names = selections.filter((n) => rx.test(n));
    if (names.length === 0) throw new Unsupported(`condition refers to unknown selection "${pat}"`);
    return names;
  };
  const primary = (): Cond => {
    const t = tokens[pos++];
    if (t === undefined) throw new Unsupported("incomplete condition");
    const lt = t.toLowerCase();
    if (lt === "(") {
      const c = orExpr();
      if (tokens[pos++] !== ")") throw new Unsupported("unbalanced parentheses");
      return c;
    }
    if (lt === "not") return { op: "not", arg: primary() };
    const of = lt.match(/^(1|all|any) of$/);
    if (of) {
      const target = tokens[pos++];
      if (!target) throw new Unsupported("incomplete 'of' condition");
      return { op: "of", quant: of[1] === "all" ? "all" : "1", names: expand(target) };
    }
    if (!selections.includes(t)) throw new Unsupported(`condition refers to unknown selection "${t}"`);
    return { op: "sel", name: t };
  };
  const andExpr = (): Cond => {
    const args = [primary()];
    while (peek() === "and") { pos++; args.push(primary()); }
    return args.length === 1 ? args[0] : { op: "and", args };
  };
  const orExpr = (): Cond => {
    const args = [andExpr()];
    while (peek() === "or") { pos++; args.push(andExpr()); }
    return args.length === 1 ? args[0] : { op: "or", args };
  };
  const c = orExpr();
  if (pos !== tokens.length) throw new Unsupported(`unexpected "${tokens[pos]}" in condition`);
  return c;
}

// ── Rule ────────────────────────────────────────────────────────────────

export function compileSigmaYaml(text: string): CompileResult {
  let docs: unknown[];
  try {
    docs = yaml.loadAll(text);
  } catch (e) {
    return { ok: false, meta: null, reason: `YAML: ${(e as Error).message.split("\n")[0]}` };
  }
  const doc = docs.find((d) => d && typeof d === "object") as Record<string, unknown> | undefined;
  if (!doc) return { ok: false, meta: null, reason: "empty document" };
  const m = meta(doc);
  try {
    if (docs.length > 1) throw new Unsupported("multi-document rule collection");
    if (doc.correlation) throw new Unsupported("correlation rule");
    if (!m.sigmaId) throw new Unsupported("rule has no id");
    const det = doc.detection as Record<string, unknown> | undefined;
    if (!det || typeof det !== "object") throw new Unsupported("no detection section");
    if (det.timeframe) throw new Unsupported("timeframe (aggregation)");
    const selections: Record<string, Selection> = {};
    for (const [name, value] of Object.entries(det)) {
      if (name === "condition" || name === "timeframe") continue;
      selections[name] = compileSelection(value);
    }
    const condTexts = strList(det.condition);
    if (condTexts.length === 0) throw new Unsupported("no condition");
    const names = Object.keys(selections);
    const conditions = condTexts.map((c) => parseCondition(c, names));
    return { ok: true, meta: m, compiled: { selections, conditions } };
  } catch (e) {
    if (e instanceof Unsupported) return { ok: false, meta: m, reason: e.message };
    return { ok: false, meta: m, reason: `compile error: ${(e as Error).message}` };
  }
}
