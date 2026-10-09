export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { checkForOverlay } from "@/lib/updates/overlay";

// POST — platform_admin, or org_admin in appliance mode (see
// isInstanceAdmin). Live query against the Enterprise overlay channel,
// only meaningful once a license is activated (see
// /api/admin/enterprise/license). A perpetual channel — this stays
// useful after the first apply too, for later overlay versions — so
// there's no "already applied" rejection here. Never installs anything.
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const result = await checkForOverlay();
  return NextResponse.json(result);
}
