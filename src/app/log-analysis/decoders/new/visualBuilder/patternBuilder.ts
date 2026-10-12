// ─────────────────────────────────────────────────────────────────────────────
// Visual decoder builder — pure pattern/check/normalize/YAML generation.
//
// Framework-free: takes a raw sample line + an ordered list of tagged spans,
// produces the exact decoder YAML the engine already consumes
// (src/lib/log-analysis/decoder-engine). Escaping of literal text is left
// entirely to the engine's own compilePattern()/escapeLiteral() — this
// module only ever concatenates raw substrings of the sample line.
// ─────────────────────────────────────────────────────────────────────────────

export type SpanType =
  | "string" | "long" | "double" | "quoted" | "between"
  | "ISO8601" | "SYSLOG" | "optional" | "discard";

export interface Span {
  id: string;
  /** Absolute offsets into the raw sample line. end is exclusive. */
  start: number;
  end: number;
  /** Dot-path field name, e.g. "source.ip". Empty only when type === "discard". */
  path: string;
  type: SpanType;
  /** Only for type === "quoted" */
  quoteChar?: '"' | "'";
  /** Only for type === "between" */
  between?: { open: string; close: string };
  /** True if start/end were auto-extended to consume adjacent delimiter chars */
  consumedBoundary?: boolean;
}

export const SPAN_TYPE_LABELS: Record<SpanType, string> = {
  string:   "Text",
  long:     "Integer",
  double:   "Decimal",
  quoted:   "Quoted string",
  between:  "Between delimiters",
  ISO8601:  "ISO 8601 timestamp",
  SYSLOG:   "Syslog timestamp",
  optional: "Optional text",
  discard:  "Ignore (discard)",
};

/** Types whose regex fragment cannot contain a literal space. */
const NO_SPACE_TYPES: ReadonlySet<SpanType> = new Set(["string", "long", "double", "ISO8601", "optional"]);

export function typeAllowsSpaces(type: SpanType): boolean {
  return !NO_SPACE_TYPES.has(type);
}

// ── Type auto-suggestion ────────────────────────────────────────────────────

const DOTTED_QUAD_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const LONG_RE = /^-?\d+$/;
const DOUBLE_RE = /^-?\d+\.\d+$/;
const ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
const SYSLOG_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}$/;

/**
 * Suggest a type for the given inner text (delimiter chars already
 * excluded). boundaryHint reflects what normalizeSpanBoundaries() detected
 * around the raw selection, if anything — a detected delimiter always wins
 * over shape-based guessing.
 */
export function suggestType(
  innerText: string,
  boundaryHint: { quoteChar?: '"' | "'"; between?: { open: string; close: string } }
): SpanType {
  if (boundaryHint.quoteChar) return "quoted";
  if (boundaryHint.between) return "between";

  const t = innerText.trim();
  // Checked before the decimal check: a dotted-quad IP would otherwise be
  // misdetected as `double`, whose regex ([0-9]+[.][0-9]*) only greedily
  // consumes the first two octets and leaves the rest unmatched.
  if (DOTTED_QUAD_RE.test(t)) return "string";
  if (LONG_RE.test(t)) return "long";
  if (DOUBLE_RE.test(t)) return "double";
  if (ISO8601_RE.test(t)) return "ISO8601";
  if (SYSLOG_RE.test(t)) return "SYSLOG";
  return "string";
}

// ── Pattern string generation ───────────────────────────────────────────────

function emitToken(span: Span): string {
  const path = span.path.trim();
  switch (span.type) {
    case "discard":  return "<~>";
    case "optional": return `<?${path}>`;
    case "long":     return `<${path}/long>`;
    case "double":   return `<${path}/double>`;
    case "quoted":   return `<${path}/quoted/${span.quoteChar ?? '"'}>`;
    case "between":  return `<${path}/between/[${span.between?.open ?? "["}][${span.between?.close ?? "]"}]>`;
    case "ISO8601":  return `<${path}/ISO8601>`;
    case "SYSLOG":   return `<${path}/SYSLOG>`;
    default:         return `<${path}>`;
  }
}

/**
 * Reconstruct the parse|event.original pattern string from the raw line +
 * spans. Literal gaps between spans are copied verbatim — compilePattern()'s
 * own escapeLiteral() is the single source of truth for escaping them, this
 * function must not attempt that itself.
 */
export function buildPatternString(rawLine: string, spans: Span[]): string {
  const sorted = [...spans].sort((a, b) => a.start - b.start);
  let out = "";
  let cursor = 0;
  for (const span of sorted) {
    out += rawLine.slice(cursor, span.start);
    out += emitToken(span);
    cursor = span.end;
  }
  out += rawLine.slice(cursor);
  return out;
}

/**
 * Literal text outside any span must not contain a stray '<' or '>' —
 * escapeLiteral() never escapes those, so compilePattern()'s TOKEN_RE would
 * misparse them as token delimiters. Returns a human-readable warning, or
 * null if the literal gaps are clean.
 */
export function findStrayAngleBrackets(rawLine: string, spans: Span[]): string | null {
  const sorted = [...spans].sort((a, b) => a.start - b.start);
  let cursor = 0;
  const gaps: string[] = [];
  for (const span of sorted) {
    gaps.push(rawLine.slice(cursor, span.start));
    cursor = span.end;
  }
  gaps.push(rawLine.slice(cursor));
  const dirty = gaps.some((g) => g.includes("<") || g.includes(">"));
  if (!dirty) return null;
  return "This line contains a literal \"<\" or \">\" outside your highlighted fields — these are reserved token delimiters in the decoder syntax and may break parsing. Highlight that portion as a field, or fix it up in the raw YAML after generating.";
}

// ── check: generation ───────────────────────────────────────────────────────

/**
 * Auto-generate a starts_with() guard from the literal prefix before the
 * first tagged span. checkEvaluator's unquote() has no escape handling, so
 * the literal is truncated before any quote character it can't safely
 * represent. Returns undefined when there's no usable prefix — omitting
 * check: entirely is valid (compileDecoder treats it as optional).
 */
export function buildCheck(rawLine: string, spans: Span[]): string | undefined {
  const firstStart = spans.length ? Math.min(...spans.map((s) => s.start)) : rawLine.length;
  let prefix = rawLine.slice(0, firstStart);
  const quoteIdx = prefix.search(/['"]/);
  if (quoteIdx >= 0) prefix = prefix.slice(0, quoteIdx);
  prefix = prefix.trimEnd();
  if (!prefix) return undefined;
  return `starts_with($event.original, '${prefix}')`;
}

// ── normalize: generation ───────────────────────────────────────────────────

export const EVENT_CATEGORIES = ["network", "web", "authentication", "process", "file", "iam", "host"] as const;

/**
 * Common ECS-style field names, mirrored from the canonical catalog in
 * src/lib/log-analysis/decoder-engine/types.ts's NormalizedLogEntry. Offered
 * as autocomplete suggestions for field naming — free text is always
 * allowed, this is a nudge toward existing conventions, not a restriction.
 */
export const COMMON_FIELD_NAMES = [
  "source.ip", "source.port", "source.domain",
  "destination.ip", "destination.port", "destination.domain",
  "network.transport", "network.protocol", "network.direction", "network.interface",
  "http.request.method", "http.request.referrer", "http.response.status_code", "http.response.bytes", "http.version",
  "url.original", "url.domain", "url.path", "url.full",
  "user.name", "user.id",
  "process.name", "process.pid", "process.command_line",
  "file.path", "file.name",
  "hash.md5", "hash.sha1", "hash.sha256",
  "observer.vendor", "observer.product", "observer.type",
  "host.name", "host.hostname", "host.ip",
  "event.action", "event.code", "event.outcome",
];

const RELATED_FIELD_RULES: { suffix: string; related: string }[] = [
  { suffix: "source.ip",      related: "related.ip" },
  { suffix: "destination.ip", related: "related.ip" },
  { suffix: "user.name",      related: "related.user" },
  { suffix: "hash.md5",       related: "related.hash" },
  { suffix: "hash.sha1",      related: "related.hash" },
  { suffix: "hash.sha256",    related: "related.hash" },
];

interface NormalizeBlockSpec {
  check?: string;
  map: [string, string][];
}

export function buildNormalizeBlocks(datasetSlug: string, category: string, spans: Span[]): NormalizeBlockSpec[] {
  const blocks: NormalizeBlockSpec[] = [
    {
      map: [
        ["event.dataset", `${datasetSlug}.custom`],
        ["event.kind", "event"],
        ["event.category", `array_append(${category})`],
      ],
    },
  ];

  const seenRelated = new Set<string>();
  for (const span of spans) {
    if (span.type === "discard") continue;
    const rule = RELATED_FIELD_RULES.find((r) => span.path === r.suffix || span.path.endsWith(`.${r.suffix}`));
    if (!rule || seenRelated.has(rule.related + span.path)) continue;
    seenRelated.add(rule.related + span.path);
    blocks.push({
      check: `exists($${span.path})`,
      map: [[rule.related, `array_append_unique($${span.path})`]],
    });
  }

  return blocks;
}

// ── Misc helpers ─────────────────────────────────────────────────────────────

/**
 * Ephemeral client-only id for React keys / span identity — never persisted,
 * never sent to the server. crypto.randomUUID() is deliberately NOT used
 * here: it's only exposed in secure contexts (HTTPS or localhost), and this
 * app is frequently reached over plain HTTP by IP on an internal network —
 * calling it there throws and silently breaks the caller (this is what was
 * breaking "Add field": SpanEditorPanel used to call it directly).
 */
export function genId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

export function slugify(title: string): string {
  return title
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "custom";
}

/** Safe embedding of a string inside single-quoted YAML — double internal quotes. */
function yamlSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

export interface DecoderMeta {
  title: string;
  author: string;
  description: string;
  category: string;
}

/**
 * existingName: when editing an already-saved decoder, pass its current
 * `name:` through unchanged instead of re-deriving one from the title.
 * PATCH /api/log-analysis/decoders/[id] takes `name` straight from the
 * submitted YAML (see def.name there) and it's a unique DB column other
 * decoders can reference via parents: — silently renaming it on every
 * visual-mode save (whenever the title changes) would be a real footgun.
 */
export function buildDecoderYaml(meta: DecoderMeta, rawLine: string, spans: Span[], existingName?: string): string {
  const slug = slugify(meta.title);
  const name = existingName ?? `decoder/${slug}/0`;
  const date = new Date().toISOString().slice(0, 10);
  const pattern = buildPatternString(rawLine, spans);
  const check = buildCheck(rawLine, spans);
  const normalizeBlocks = buildNormalizeBlocks(slug, meta.category, spans);

  const lines: string[] = [];
  lines.push(`name: ${name}`);
  lines.push(`enabled: true`);
  lines.push(``);
  lines.push(`metadata:`);
  lines.push(`  title: ${yamlSingleQuote(meta.title || "My Custom Integration")}`);
  lines.push(`  author: ${yamlSingleQuote(meta.author)}`);
  lines.push(`  date: '${date}'`);
  lines.push(`  description: ${yamlSingleQuote(meta.description || "Generated with the visual decoder builder")}`);
  lines.push(``);
  if (check) {
    lines.push(`check: >-`);
    lines.push(`  ${check}`);
  } else {
    lines.push(`# No distinguishing prefix was found for this sample line, so no check:`);
    lines.push(`# guard was generated — this decoder will attempt to parse every log line.`);
    lines.push(`# Consider adding one by hand for better discrimination.`);
  }
  lines.push(``);
  lines.push(`parse|event.original:`);
  lines.push(`  - ${yamlSingleQuote(pattern)}`);
  lines.push(``);
  lines.push(`normalize:`);
  for (const block of normalizeBlocks) {
    if (block.check) lines.push(`  - check: ${block.check}`);
    else lines.push(`  - map:`);
    if (block.check) lines.push(`    map:`);
    for (const [k, v] of block.map) {
      lines.push(`      - ${k}: ${v}`);
    }
  }
  lines.push(``);

  return lines.join("\n");
}
