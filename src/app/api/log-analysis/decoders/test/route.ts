export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { z }                from "zod";
import { compileDecoder, applyDecoder, matchDecoder, loadDecoders, buildBaseContext } from "@/lib/log-analysis/decoder-engine/engine";

const TestSchema = z.object({
  /** Raw YAML of the decoder to test (may not be saved yet) */
  yamlContent: z.string().min(1).optional(),
  /** OR: test by saved decoder ID — pass a raw log line against a stored decoder */
  decoderId: z.string().uuid().optional(),
  /** The raw log line to test */
  logLine: z.string().min(1),
});

// ── POST /api/log-analysis/decoders/test ────────────────────────────────────
export async function POST(req: NextRequest) {
  try {
    await getActorOrThrow(req);
    const body  = await req.json();
    const input = TestSchema.parse(body);

    let result;
    let matchedDecoder: string | null = null;
    let validationErrors: string[] = [];

    if (input.yamlContent) {
      // Test against provided YAML (not yet saved)
      let def;
      try {
        def = compileDecoder(input.yamlContent, false);
      } catch (err) {
        return NextResponse.json({
          matched:          false,
          validationErrors: [String(err)],
          output:           null,
        });
      }

      // Check if decoder matches the log line
      const checkCtx = buildBaseContext(input.logLine);
      const { evaluateCheck } = await import("@/lib/log-analysis/decoder-engine/checkEvaluator");
      const checkPassed = def.check ? evaluateCheck(def.check, checkCtx) : true;

      if (!checkPassed) {
        return NextResponse.json({
          matched:          false,
          matchedDecoder:   def.name,
          validationErrors: ["check: condition did not match this log line"],
          output:           null,
        });
      }

      result         = applyDecoder(def, input.logLine);
      matchedDecoder = def.name;

      // Warn about leftover _tmp fields
      const leftover = Object.keys(result).filter((k) => k.startsWith("_"));
      if (leftover.length > 0) {
        validationErrors = [`Temporary fields not cleaned up: ${leftover.join(", ")}`];
      }
    } else {
      // Test against all loaded decoders
      await loadDecoders();
      const decoder = matchDecoder(input.logLine);

      if (!decoder) {
        return NextResponse.json({
          matched:          false,
          matchedDecoder:   null,
          validationErrors: ["No decoder matched this log line"],
          output:           null,
        });
      }

      result         = applyDecoder(decoder, input.logLine);
      matchedDecoder = decoder.name;
    }

    return NextResponse.json({
      matched:        true,
      matchedDecoder,
      output:         result,
      validationErrors,
    });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    if (err instanceof z.ZodError) return NextResponse.json({ error: "validation", detail: err.errors }, { status: 422 });
    return NextResponse.json({ error: "server_error", detail: String(err) }, { status: 500 });
  }
}
