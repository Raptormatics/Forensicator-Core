export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import os from "os";
import path from "path";
import { createHash, randomUUID } from "crypto";
import { z } from "zod";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { currentProgress } from "@/lib/updates/paths";
import { checkForUpdate, getChannel } from "@/lib/updates/online";
import { startInstall, actorIp } from "@/lib/updates/install";

const MAX_PACKAGE_BYTES = 500 * 1024 * 1024;
const bodySchema = z.object({ allowDowngrade: z.boolean().optional().default(false) });

// POST — platform_admin, or org_admin in appliance mode (see
// isInstanceAdmin). Downloads the package the update server currently
// points to (re-resolved here, never trusting a client-supplied URL) and
// hands it to the same privileged installer the offline upload path uses.
// The download itself is unprivileged (a plain outbound fetch); only
// deploy/forensicator-update.sh (invoked next) runs as root, and it
// re-verifies the package's signature regardless of how it got here.
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  if (currentProgress()) {
    return NextResponse.json({ error: "An update is already in progress." }, { status: 409 });
  }

  const { allowDowngrade } = bodySchema.parse(await req.json().catch(() => ({})));

  const check = await checkForUpdate();
  if (!check.configured) {
    return NextResponse.json({ error: "No update server configured." }, { status: 400 });
  }
  if (!check.ok) {
    return NextResponse.json({ error: check.error }, { status: 502 });
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
      { error: "Downloaded package's checksum does not match the update server's manifest — refusing to install." },
      { status: 502 }
    );
  }

  const tmpPath = path.join(os.tmpdir(), `forensicator-update-${randomUUID()}.fpk`);
  fs.writeFileSync(tmpPath, bytes);

  await startInstall({
    packagePath: tmpPath,
    allowDowngrade,
    source: "online",
    actor,
    actorIp: actorIp(req.headers),
    metadata: { version: check.latest.version, channel: getChannel(), packageUrl: check.latest.packageUrl },
  });

  return NextResponse.json({ started: true }, { status: 202 });
}
