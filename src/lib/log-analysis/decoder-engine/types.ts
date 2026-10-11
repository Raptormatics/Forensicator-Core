// ─────────────────────────────────────────────────────────────────────────────
// Decoder Engine — shared type definitions
// ─────────────────────────────────────────────────────────────────────────────

/** A single compiled pattern field descriptor */
export interface ParsedField {
  /** Original dot-path (e.g. "source.ip") */
  path: string;
  /** Named-group key in the RegExp (dots replaced with __) */
  groupName: string;
  /** How to post-process the captured string */
  type: "string" | "long" | "double" | "quoted-double" | "quoted-single" | "between" | "ISO8601" | "SYSLOG" | "discard" | "optional";
  /** For "between" type: opening and closing delimiter */
  between?: { open: string; close: string };
}

/** A compiled parse pattern */
export interface CompiledPattern {
  regex: RegExp;
  fields: ParsedField[];
}

/** One normalize block: optional guard + field→expression map */
export interface NormalizeBlock {
  check?: string;
  map: Record<string, unknown>; // YAML values may be string, number, or boolean
}

/** Parsed + compiled decoder definition */
export interface DecoderDef {
  /** Unique name, e.g. decoder/fortinet-fortigate/0 */
  name: string;
  enabled: boolean;
  isBuiltin: boolean;
  /** Display title */
  title?: string;
  description?: string;
  /** Parent decoder names to run first */
  parents?: string[];
  /** Check expression evaluated before any parsing */
  check?: string;
  /** Compiled parse patterns (from parse|event.original) */
  patterns: CompiledPattern[];
  /** Normalize blocks */
  normalize: NormalizeBlock[];
  /** Raw YAML source (for export/display) */
  yaml: string;
}

/**
 * Canonical normalized event produced by the decoder engine.
 * Fields follow ECS (Elastic Common Schema) dot-notation.
 */
export interface NormalizedLogEntry {
  "@timestamp"?: string;
  message?: string;
  original?: string;

  "event.kind"?: string;
  "event.category"?: string[];
  "event.type"?: string[];
  "event.outcome"?: string;
  "event.dataset"?: string;
  "event.code"?: string;
  "event.severity"?: number;
  "event.action"?: string;

  "source.ip"?: string;
  "source.port"?: number;
  "source.domain"?: string;

  "destination.ip"?: string;
  "destination.port"?: number;
  "destination.domain"?: string;

  "network.transport"?: string;
  "network.protocol"?: string;
  "network.direction"?: string;
  "network.interface"?: string;

  "http.request.method"?: string;
  "http.request.referrer"?: string;
  "http.response.status_code"?: number;
  "http.response.bytes"?: number;
  "http.version"?: string;

  "url.original"?: string;
  "url.domain"?: string;
  "url.path"?: string;
  "url.full"?: string;

  "user.name"?: string;
  "user.id"?: string;

  "process.name"?: string;
  "process.pid"?: number;
  "process.command_line"?: string;

  "file.path"?: string;
  "file.name"?: string;

  "hash.md5"?: string;
  "hash.sha1"?: string;
  "hash.sha256"?: string;

  "observer.vendor"?: string;
  "observer.product"?: string;
  "observer.type"?: string;

  "host.name"?: string;
  "host.hostname"?: string;
  "host.ip"?: string;

  "related.ip"?: string[];
  "related.user"?: string[];
  "related.hash"?: string[];

  /** Catch-all for decoder-produced fields not in the canonical list */
  [key: string]: unknown;
}

/** Raw YAML decoder descriptor (as parsed by js-yaml) */
export interface DecoderYaml {
  name: string;
  enabled?: boolean;
  metadata?: {
    title?: string;
    author?: string;
    date?: string;
    description?: string;
  };
  parents?: string[];
  check?: string;
  [parseKey: string]: unknown; // parse|event.original: string[]
  normalize?: Array<{
    check?: string;
    map?: Record<string, string>[];
  }>;
}
