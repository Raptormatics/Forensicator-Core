export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import os from "os";
import path from "path";
import { randomUUID } from "crypto";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { currentProgress } from "@/lib/updates/paths";
import { startInstall, actorIp } from "@/lib/updates/install";
import { containerUpdateBlockedResponse } from "@/lib/updates/container-guard";

const MAX_PACKAGE_BYTES = 500 * 1024 * 1024;

// POST — unrestricted (Core's sole user). Uploads a signed .fpk, hands it to the privileged
// installer via the scoped sudoers rule, and returns immediately — the
// installer will restart the very process handling this request, so the
// Admin UI tracks progress by polling GET .../status.
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }


  const blocked = containerUpdateBlockedResponse();
  if (blocked) return blocked;

  if (currentProgress()) {
    return NextResponse.json({ error: "An update is already in progress." }, { status: 409 });
  }

  let formData: FormData;
  try {
    formData = await req.formData();
  } catch {
    return NextResponse.json({ error: "Expected a multipart/form-data upload." }, { status: 400 });
  }
  const upload = formData.get("file");
  const allowDowngrade = formData.get("allowDowngrade") === "true";

  if (!(upload instanceof File)) {
    return NextResponse.json({ error: "Upload a .fpk package in the form field named file." }, { status: 400 });
  }
  if (upload.size > MAX_PACKAGE_BYTES) {
    return NextResponse.json({ error: "Package exceeds the 500 MB limit." }, { status: 413 });
  }

  const tmpPath = path.join(os.tmpdir(), `forensicator-update-${randomUUID()}.fpk`);
  const bytes = Buffer.from(await upload.arrayBuffer());
  fs.writeFileSync(tmpPath, bytes);

  await startInstall({
    packagePath: tmpPath,
    allowDowngrade,
    source: "offline",
    actor,
    actorIp: actorIp(req.headers),
    metadata: { fileName: upload.name, sizeBytes: upload.size },
  });

  return NextResponse.json({ started: true }, { status: 202 });
}
