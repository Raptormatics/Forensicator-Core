// ─────────────────────────────────────────────────────────────────────────────
// Pattern Parser — compiles <field/type> template strings into named-group RegExp
// ─────────────────────────────────────────────────────────────────────────────

import type { CompiledPattern, ParsedField } from "./types";

// Token regex: matches <field>, <field/type>, <?field>, <~>, <field/between/[X][Y]>
const TOKEN_RE = /<([^>]+)>/g;

/** Escape metacharacters in literal portions of a pattern (no \d / \S — per spec) */
function escapeLiteral(s: string): string {
  return s.replace(/[$()*+.[\]^{|}\\/?]/g, "\\$&");
}

/** Convert dot-path field name to a valid JS named-capture-group identifier */
export function pathToGroupName(path: string, index: number): string {
  return path.replace(/[^a-zA-Z0-9]/g, "_") + "_" + index;
}

/** Reverse: restore the dot-path from the group name */
export function groupNameToPath(groupName: string): string {
  // We stored original path as metadata — this function is a fallback
  return groupName.replace(/__/g, ".").replace(/_(\d+)$/, "");
}

/** Build the regex fragment and ParsedField descriptor for one token */
function tokenToFragment(
  tokenInner: string,
  index: number
): { fragment: string; field: ParsedField | null } {
  // <~> — discard (unnamed capture)
  if (tokenInner.trim() === "~") {
    return { fragment: "[^ ]+", field: null };
  }

  // <?field> — optional field
  if (tokenInner.startsWith("?")) {
    const path = tokenInner.slice(1).trim();
    const groupName = pathToGroupName(path, index);
    return {
      fragment: `(?<${groupName}>[^ ]+)?`,
      field: { path, groupName, type: "optional" },
    };
  }

  const parts = tokenInner.split("/");
  const path = parts[0].trim();
  const typeHint = parts[1]?.trim().toLowerCase();
  const groupName = pathToGroupName(path, index);

  // <field/between/[X][Y]>
  //
  // X and Y are extracted by stripping the outer [ ] wrapper and splitting
  // the remainder on the first "][" — NOT via two independent ^\[...\]/
  // \[...\]$ regexes, which have no way to know where X ends and Y begins:
  // openMatch always finds the first bracket pair from the start, but
  // closeMatch also starts scanning from that same leftmost '[' (its only
  // anchor is the string's end), so for any X/Y longer than a char, or
  // either containing '[' or ']' itself (the common case for bracketed
  // values, e.g. timestamps), it silently captured garbage — verified via
  // <foo/between/[abc][xyz]> incorrectly producing close: "abc][xyz".
  if (typeHint === "between" && parts[2]) {
    const betweenSpec = parts[2];
    let open = "(", close = ")";
    if (betweenSpec.length >= 4 && betweenSpec.startsWith("[") && betweenSpec.endsWith("]")) {
      const middle = betweenSpec.slice(1, -1);
      const splitIdx = middle.indexOf("][");
      if (splitIdx !== -1) {
        open = middle.slice(0, splitIdx);
        close = middle.slice(splitIdx + 2);
      }
    }
    const escapedOpen = escapeLiteral(open);
    const escapedClose = escapeLiteral(close);
    return {
      fragment: `${escapedOpen}(?<${groupName}>[^${escapedClose}]*)${escapedClose}`,
      field: { path, groupName, type: "between", between: { open, close } },
    };
  }

  // <field/quoted/">  or  <field/quoted/'>
  if (typeHint === "quoted") {
    const quoteChar = parts[2]?.trim() ?? '"';
    const escaped = escapeLiteral(quoteChar);
    const type = quoteChar === "'" ? "quoted-single" : "quoted-double";
    return {
      fragment: `${escaped}(?<${groupName}>[^${escaped}]*)${escaped}`,
      field: { path, groupName, type },
    };
  }

  // <field/long>  — integer digits
  if (typeHint === "long") {
    return {
      fragment: `(?<${groupName}>[0-9]+)`,
      field: { path, groupName, type: "long" },
    };
  }

  // <field/double>  — decimal number
  if (typeHint === "double") {
    return {
      fragment: `(?<${groupName}>[0-9]+[.][0-9]*)`,
      field: { path, groupName, type: "double" },
    };
  }

  // <field/ISO8601>
  if (typeHint === "iso8601") {
    return {
      fragment: `(?<${groupName}>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?)`,
      field: { path, groupName, type: "ISO8601" },
    };
  }

  // <field/SYSLOG>  — Jan 15 12:00:00
  if (typeHint === "syslog") {
    return {
      fragment: `(?<${groupName}>[A-Z][a-z]{2}[ ]+[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2})`,
      field: { path, groupName, type: "SYSLOG" },
    };
  }

  // <field/@timestamp>  — common alias
  if (path === "@timestamp" || typeHint === "timestamp") {
    return {
      fragment: `(?<${groupName}>[^ ]+)`,
      field: { path, groupName, type: "string" },
    };
  }

  // Default: any non-whitespace token
  return {
    fragment: `(?<${groupName}>[^ ]+)`,
    field: { path, groupName, type: "string" },
  };
}

/**
 * Compile a decoder pattern string into a { regex, fields } object.
 *
 * Example:
 *   input:  "GET <url.path> HTTP/<http.version>"
 *   output: /^GET (?<url__path_0>[^ ]+) HTTP\/(?<http__version_1>[^ ]+)$/
 */
export function compilePattern(pattern: string): CompiledPattern {
  const fields: ParsedField[] = [];
  let regexSource = "";
  let lastIndex = 0;
  let tokenIndex = 0;

  TOKEN_RE.lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = TOKEN_RE.exec(pattern)) !== null) {
    // Escape literal text before this token
    const literal = pattern.slice(lastIndex, match.index);
    regexSource += escapeLiteral(literal);

    const { fragment, field } = tokenToFragment(match[1], tokenIndex++);
    regexSource += fragment;
    if (field) fields.push(field);

    lastIndex = TOKEN_RE.lastIndex;
  }

  // Escape any trailing literal
  regexSource += escapeLiteral(pattern.slice(lastIndex));

  return {
    // 'd' (hasIndices) only adds match.indices — never changes what matches,
    // so this is safe for every existing caller. Used by the visual decoder
    // builder to recover character offsets when reverse-parsing an existing
    // decoder's pattern back into editable spans.
    regex: new RegExp("^" + regexSource + "$", "d"),
    fields,
  };
}

/**
 * Try each compiled pattern against the raw line.
 * Returns a field-value map on first match, null if none match.
 */
export function matchPatterns(
  patterns: CompiledPattern[],
  raw: string
): Record<string, unknown> | null {
  for (const { regex, fields } of patterns) {
    const m = regex.exec(raw);
    if (!m) continue;

    const result: Record<string, unknown> = {};
    for (const field of fields) {
      const raw_val = m.groups?.[field.groupName];
      if (raw_val === undefined || raw_val === null) continue;

      switch (field.type) {
        case "long":
          result[field.path] = parseInt(raw_val, 10);
          break;
        case "double":
          result[field.path] = parseFloat(raw_val);
          break;
        case "discard":
          break;
        case "optional":
          if (raw_val !== "") result[field.path] = raw_val;
          break;
        default:
          result[field.path] = raw_val;
      }
    }
    return result;
  }
  return null;
}
