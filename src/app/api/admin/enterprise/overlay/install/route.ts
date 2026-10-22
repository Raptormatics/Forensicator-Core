export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import os from "os";
import path from "path";
import { randomUUID } from "crypto";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { currentProgress } from "@/lib/updates/paths";
import { checkForOverlay, downloadOverlayPackage } from "@/lib/updates/overlay";
import { startOverlayInstall, actorIp } from "@/lib/updates/install";
import { containerUpdateBlockedResponse } from "@/lib/updates/container-guard";


// POST — unrestricted (Core's sole user). Re-resolves the overlay channel
// here, then downloads the package from the license server with the
// activated license (downloadOverlayPackage) — the .fpk has no public URL.
// Requires an activated license (checkForOverlay() returns
// licensed:false otherwise); the download itself is unprivileged, only
// deploy/forensicator-update.sh's --overlay mode (invoked next) runs as
// root, and it re-verifies the package's signature regardless.
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }


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

  const download = await downloadOverlayPackage(check.latest);
  if (!download.ok) return NextResponse.json({ error: download.error }, { status: 502 });

  const tmpPath = path.join(os.tmpdir(), `forensicator-overlay-${randomUUID()}.fpk`);
  fs.writeFileSync(tmpPath, download.bytes);

  await startOverlayInstall({
    packagePath: tmpPath,
    actor,
    actorIp: actorIp(req.headers),
    metadata: { version: check.latest.version, source: "license-server" },
  });

  return NextResponse.json({ started: true }, { status: 202 });
}
