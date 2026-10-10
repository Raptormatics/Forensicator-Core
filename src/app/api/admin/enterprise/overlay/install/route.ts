export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import os from "os";
import path from "path";
import { createHash, randomUUID } from "crypto";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { currentProgress } from "@/lib/updates/paths";
import { checkForOverlay } from "@/lib/updates/overlay";
import { startOverlayInstall, actorIp } from "@/lib/updates/install";
import { containerUpdateBlockedResponse } from "@/lib/updates/container-guard";

const MAX_PACKAGE_BYTES = 500 * 1024 * 1024;

// POST — platform_admin, or org_admin in appliance mode (see
// isInstanceAdmin). Re-resolves the overlay channel here, never trusting
// a client-supplied URL — same pattern as the regular online-install
// route. Requires an activated license (checkForOverlay() returns
// licensed:false otherwise); the download itself is unprivileged, only
// deploy/forensicator-update.sh's --overlay mode (invoked next) runs as
// root, and it re-verifies the package's signature regardless.
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const blocked = containerUpdateBlockedResponse();
  if (blocked) return blocked;

  if (currentProgress()) {
    return NextResponse.json({ error: "An update is already in progress." }, { status: 409 });
  }

  const check = await checkForOverlay();
  if (!check.licensed) {
    return NextResponse.json({ error: "No Enterprise license activated — activate one under Settings -> License first." }, { status: 403 });
  }
  if (!check.ok) {
    return NextResponse.json({ error: check.error }, { status: 502 });
  }
  // Authoritatively re-checked inside deploy/forensicator-update.sh's
  // --overlay mode too — this is just a clearer error before a download
  // even starts, not the real trust boundary.
  if (!check.coreVersionSatisfied) {
    return NextResponse.json(
      { error: `This Enterprise update requires Core v${check.latest.requiresCoreVersion} or later — install the pending Core update first.` },
      { status: 409 }
    );
  }

  const res = await fetch(check.latest.packageUrl, { signal: AbortSignal.timeout(120_000) });
  if (!res.ok) {
    return NextResponse.json({ error: `Failed to download package: HTTP ${res.status}` }, { status: 502 });
  }
  const bytes = Buffer.from(await res.arrayBuffer());
  if (bytes.length > MAX_PACKAGE_BYTES) {
    return NextResponse.json({ error: "Downloaded package exceeds the 500 MB limit." }, { status: 502 });
  }

  const actualSha256 = createHash("sha256").update(bytes).digest("hex");
  if (actualSha256 !== check.latest.packageSha256) {
    return NextResponse.json(
      { error: "Downloaded package's checksum does not match the overlay server's manifest — refusing to install." },
      { status: 502 }
    );
  }

  const tmpPath = path.join(os.tmpdir(), `forensicator-overlay-${randomUUID()}.fpk`);
  fs.writeFileSync(tmpPath, bytes);

  await startOverlayInstall({
    packagePath: tmpPath,
    actor,
    actorIp: actorIp(req.headers),
    metadata: { version: check.latest.version, packageUrl: check.latest.packageUrl },
  });

  return NextResponse.json({ started: true }, { status: 202 });
}
