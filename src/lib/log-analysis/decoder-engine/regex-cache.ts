// ─────────────────────────────────────────────────────────────────────────────
// Shared regex cache — compile once at load time, zero cost at event time.
// All decode-engine modules share this singleton.
// ─────────────────────────────────────────────────────────────────────────────

const _cache = new Map<string, RegExp>();

/**
 * Return a compiled RegExp for `pattern` + optional `flags`, compiling it
 * the first time it is seen. Never throws — returns a never-match regex
 * if the pattern is invalid so decoding degrades gracefully.
 */
export function getRegex(pattern: string, flags = ""): RegExp {
  const key = flags ? `${flags}:${pattern}` : pattern;
  let re = _cache.get(key);
  if (!re) {
    try {
      re = new RegExp(pattern, flags);
    } catch {
      // Invalid pattern — use a never-match sentinel
      re = /(?!)/;
    }
    _cache.set(key, re);
  }
  return re;
}

/** Pre-compile all regex patterns found in a decoder's YAML text. */
export function precompileDecoderPatterns(yamlText: string): void {
  // Find every regex_extract / regex_match call and pre-warm the cache
  const regex = /regex_(?:extract|match)\s*\([^,)]+,\s*['"](.+?)['"]\s*[\),]/g;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(yamlText)) !== null) {
    getRegex(m[1]); // compile + cache
  }
}

/** Number of patterns currently cached (for diagnostics). */
export function cacheSize(): number {
  return _cache.size;
}
