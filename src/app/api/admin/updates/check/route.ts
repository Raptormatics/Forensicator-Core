export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { checkForUpdate } from "@/lib/updates/online";
import { installedVersion } from "@/lib/updates/paths";
import { isNewerVersion } from "@/lib/updates/version";
import { containerUpdateBlockedResponse } from "@/lib/updates/container-guard";

// POST — platform_admin, or org_admin in appliance mode (see
// isInstanceAdmin). Live query against UPDATE_SERVER_URL (if configured)
// for the latest version on the currently-selected channel. Never installs
// anything — see /api/admin/updates/install-online for that.
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const blocked = containerUpdateBlockedResponse();
  if (blocked) return blocked;

  const result = await checkForUpdate();
  if (!result.configured || !result.ok) {
    return NextResponse.json(result);
  }

  return NextResponse.json({
    ...result,
    updateAvailable: isNewerVersion(result.latest.version, installedVersion()),
  });
}
