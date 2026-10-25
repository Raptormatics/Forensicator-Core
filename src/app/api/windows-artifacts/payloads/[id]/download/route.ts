/**
 * GET /api/windows-artifacts/payloads/[id]/download — streams back the
 * RC4-decrypted bytes of a Windows Defender quarantine ResourceData
 * payload (see defender-quarantine-parse.py). Same auth-gated, plain
 * fs.readFileSync + Content-Disposition pattern as the existing
 * ram-analysis malfind-region dump route — the only difference is this
 * file is already decrypted and sitting on disk (no re-invocation of a
 * parser needed at download time).
 *
 * This hands back a real (if previously quarantined) malware sample —
 * intentional, per the windows-artifacts plan's Decisions (the user
 * explicitly chose "store the decrypted file too" over hash+metadata
 * only) — gated behind the same requireAuth every other Windows
 * Artifacts route already uses.
 */
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { actorOr401, guardOrgAccess } from "@/lib/auth/org-access";

type Params = { params: Promise<{ id: string }> };

export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  const orgActor = await actorOr401(req);
  if (orgActor instanceof NextResponse) return orgActor;
  const orgDenied = await guardOrgAccess(orgActor, { quarantinePayloadId: params.id });
  if (orgDenied) return orgDenied;
  try {
    await requireAuth(req);
    const { id } = params;

    const payload = await prisma.defenderQuarantinePayload.findUnique({
      where: { id },
      select: { sourceFileName: true, sha256: true, magicValid: true, decryptedStoragePath: true },
    });
    if (!payload) {
      return NextResponse.json({ error: "not_found" }, { status: 404 });
    }
    if (!payload.magicValid || !payload.decryptedStoragePath) {
      return NextResponse.json({ error: "payload_not_decrypted", message: "This file's RC4 header magic didn't validate — no decrypted payload is available for it." }, { status: 400 });
    }
    if (!fs.existsSync(payload.decryptedStoragePath)) {
      return NextResponse.json({ error: "file_missing" }, { status: 404 });
    }

    const bytes = fs.readFileSync(payload.decryptedStoragePath);
    const safeSource = path.basename(payload.sourceFileName).replace(/[^a-zA-Z0-9._-]/g, "_");
    const filename = `${safeSource}-decrypted${payload.sha256 ? `-${payload.sha256.slice(0, 12)}` : ""}.bin`;

    return new NextResponse(new Uint8Array(bytes), {
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Content-Length": String(bytes.length),
      },
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
