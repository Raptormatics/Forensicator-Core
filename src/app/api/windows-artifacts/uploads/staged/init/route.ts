/**
 * POST /api/windows-artifacts/uploads/staged/init — starts a chunked
 * Windows Artifact file upload (used for a large single file — chiefly
 * $MFT — ahead of the rest of a collection's multipart POST). See
 * src/prisma/schema's WindowsArtifactStagedFile doc comment and
 * src/lib/shared/chunked-upload-state.ts for why this exists: `await
 * req.formData()` buffers the whole multipart body in memory, which OOMs
 * or takes 50+ seconds per few hundred MB — confirmed directly in this
 * session. Mirrors src/app/api/ram-analysis/uploads/chunked/init/route.ts,
 * minus the RAM-specific osType/case/hostname/etc. fields this doesn't
 * need — a staged file isn't tied to a role/upload/case until the main
 * upload route consumes it by stagedId.
 */
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { getWinArtifactsDir, getWinArtifactsChunkSize, getWinArtifactsMaxUploadBytes } from "@/lib/settings/system";
import { registerNewHash } from "@/lib/shared/chunked-upload-state";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

export async function POST(req: NextRequest) {
  try {
    const actor = await requireAuth(req);
    const body = await req.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "invalid_body", message: "Expected a JSON body." }, { status: 400 });
    }

    const filename = typeof body.filename === "string" ? body.filename.trim() : "";
    if (!filename) {
      return NextResponse.json({ error: "invalid_filename", message: "filename is required." }, { status: 400 });
    }

    let totalBytes: bigint;
    try {
      totalBytes = BigInt(body.totalBytes);
      if (totalBytes <= BigInt(0)) throw new Error("non-positive");
    } catch {
      return NextResponse.json({ error: "invalid_size", message: "totalBytes must be a positive integer." }, { status: 400 });
    }

    // A single staged file obviously can't exceed the whole collection's
    // own cap — reuse it as the per-file ceiling too rather than inventing
    // a separate setting.
    const maxBytes = await getWinArtifactsMaxUploadBytes();
    if (totalBytes > BigInt(maxBytes)) {
      return NextResponse.json(
        { error: "file_too_large", message: `Maximum file size is ${(maxBytes / (1024 ** 3)).toFixed(1)} GB.` },
        { status: 413 }
      );
    }

    const winArtifactsDir = await getWinArtifactsDir();
    const stagedDir = path.join(winArtifactsDir, "staged");
    fs.mkdirSync(stagedDir, { recursive: true });

    // Best-effort disk-space pre-check — reject up front rather than
    // discovering ENOSPC deep into a multi-GB upload. Not fatal if statfs
    // itself fails — proceed and let the actual writes surface any real
    // problem, same posture as RAM's init route.
    try {
      const stats = await fs.promises.statfs(stagedDir);
      const freeBytes = BigInt(stats.bavail) * BigInt(stats.bsize);
      if (freeBytes < totalBytes) {
        return NextResponse.json(
          { error: "insufficient_disk_space", message: "The server does not have enough free disk space for this upload." },
          { status: 507 }
        );
      }
    } catch {
      // Ignore — see comment above.
    }

    const stagedId = crypto.randomUUID();
    const storagePath = path.join(stagedDir, `${stagedId}.partial`);
    fs.closeSync(fs.openSync(storagePath, "w"));

    const chunkSize = await getWinArtifactsChunkSize();

    await prisma.windowsArtifactStagedFile.create({
      data: {
        id: stagedId,
        filename,
        totalBytes,
        storagePath,
        uploadedById: actor.id,
        expiresAt: new Date(Date.now() + SESSION_TTL_MS),
      },
    });

    registerNewHash(stagedId);

    return NextResponse.json({ stagedId, chunkSize }, { status: 201 });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[windows-artifacts/staged/init] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
