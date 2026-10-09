export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { installedVersion, listBackups, currentProgress } from "@/lib/updates/paths";
import { getDeltaState } from "@/lib/updates/overlay";
import { getActivationState } from "@/lib/license/activation";

// GET — platform_admin, or org_admin in appliance mode (see
// isInstanceAdmin). System-level (not per-org), same tier as /licenses.
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  return NextResponse.json({
    // installedVersion is Core's own version, exactly as before — this
    // keeps meaning "Core version" even once an overlay is applied; it's
    // never touched by applying or replaying one. See delta below for
    // the Enterprise overlay's own, independent version.
    installedVersion: installedVersion(),
    backups: listBackups(),
    progress: currentProgress(),
    delta: getDeltaState(),
    licensed: getActivationState().valid,
  });
}
