export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { seedBuiltinDecoders }        from "@/lib/log-analysis/decoder-engine/seed";
import { loadDecoders }               from "@/lib/log-analysis/decoder-engine/engine";

// ── POST /api/log-analysis/decoders/seed ────────────────────────────────────
// Admin-only: seed (or re-seed) all built-in decoder YAML files into the DB.
export async function POST(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);

    if (actor.role !== "platform_admin" && actor.role !== "org_admin") {
      return NextResponse.json({ error: "forbidden" }, { status: 403 });
    }

    const result = await seedBuiltinDecoders();

    // Reload engine with freshly seeded decoders
    await loadDecoders();

    return NextResponse.json({
      success: true,
      seeded:  result.seeded,
      errors:  result.errors,
    });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error", detail: String(err) }, { status: 500 });
  }
}
