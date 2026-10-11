// ─────────────────────────────────────────────────────────────────────────────
// Normalize Runner — executes normalize[] blocks sequentially
// ─────────────────────────────────────────────────────────────────────────────

import type { NormalizeBlock } from "./types";
import { evaluateCheck }      from "./checkEvaluator";
import { resolveExpression, applyValue } from "./functions";

/**
 * Execute the normalize array against the given context.
 * Returns the mutated context (modified in-place for performance).
 *
 * Each block is processed as:
 *   1. If block.check is present and evaluates false → skip block
 *   2. For each (targetField, expression) in block.map → resolve + assign
 */
export function runNormalize(
  blocks: NormalizeBlock[],
  context: Record<string, unknown>
): Record<string, unknown> {
  const ctx = { ...context };

  for (const block of blocks) {
    // Guard: skip if check evaluates false
    if (block.check && !evaluateCheck(block.check, ctx)) continue;

    for (const [targetField, expression] of Object.entries(block.map)) {
      // Defensively coerce — YAML can produce numbers/booleans as map values
      const safeExpr: unknown =
        expression === null || expression === undefined
          ? undefined
          : typeof expression === "string"
          ? expression
          : expression;
      const resolved = resolveExpression(safeExpr, ctx, targetField);
      applyValue(ctx, targetField, resolved);
    }
  }

  // Clean up internal engine bookkeeping keys from the output:
  // - _ prefixed temp fields (decoder should call delete(), but clean up anyway)
  // - __json__ (the parsed JSON object injected by engine for field resolution)
  for (const key of Object.keys(ctx)) {
    if (key === "__json__" || key === "__json_keys__") {
      delete ctx[key];
      continue;
    }
    if (key.startsWith("_") && !key.startsWith("__")) {
      delete ctx[key];
    }
  }

  return ctx;
}
