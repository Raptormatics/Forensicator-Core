export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { seedBuiltinWinArtifactRules } from "@/lib/windows-artifacts/rule-engine/seed";

// ── POST /api/windows-artifacts/rules/seed ───────────────────────────────────
// Seed (or re-seed) the bundled starter ruleset into the DB.
export async function POST(req: NextRequest) {
  try {
    await getActorOrThrow(req);

    const result = await seedBuiltinWinArtifactRules();

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
