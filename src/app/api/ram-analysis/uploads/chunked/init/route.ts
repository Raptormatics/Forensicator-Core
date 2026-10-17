/**
 * POST /api/ram-analysis/uploads/chunked/init — starts a chunked RAM upload
 * session. See src/prisma/schema.prisma's RamUploadSession doc comment and
 * src/lib/shared/chunked-upload-state.ts for why this exists
 * (Cloudflare Tunnel's own edge-enforced body-size cap).
 */
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { getRamDir, getRamChunkSize } from "@/lib/settings/system";
import { ALLOWED_OS_TYPES, getMaxBytes, matchedExtension } from "@/lib/ram-analysis/upload-shared";
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

    const osType = typeof body.osType === "string" ? body.osType : "";
    const filename = typeof body.filename === "string" ? body.filename.trim() : "";
    const totalBytesRaw = body.totalBytes;
    const caseId = typeof body.caseId === "string" ? body.caseId : "";

    if (!osType || !ALLOWED_OS_TYPES.includes(osType)) {
      return NextResponse.json({ error: "invalid_os_type", message: "Select a valid operating system." }, { status: 400 });
    }
    const ext = filename ? matchedExtension(filename, osType) : null;
    if (!filename || !ext) {
      return NextResponse.json({ error: "invalid_file_type", message: `Provide a filename with a supported extension for ${osType}.` }, { status: 400 });
    }
    if (!caseId) {
      return NextResponse.json({ error: "missing_case", message: "Every RAM upload must be linked to a case." }, { status: 400 });
    }

    let totalBytes: bigint;
    try {
      totalBytes = BigInt(totalBytesRaw);
      if (totalBytes <= BigInt(0)) throw new Error("non-positive");
    } catch {
      return NextResponse.json({ error: "invalid_size", message: "totalBytes must be a positive integer." }, { status: 400 });
    }

    const maxBytes = getMaxBytes();
    if (totalBytes > BigInt(maxBytes)) {
      return NextResponse.json(
        { error: "file_too_large", message: `Maximum RAM image size is ${(maxBytes / (1024 ** 3)).toFixed(0)} GB.` },
        { status: 413 }
      );
    }

    const kase = await prisma.case.findUnique({ where: { id: caseId }, select: { id: true, status: true } });
    if (!kase) {
      return NextResponse.json({ error: "invalid_case", message: "The specified case does not exist." }, { status: 400 });
    }
    if (kase.status === "closed") {
      return NextResponse.json({ error: "case_closed", message: "This case is closed and cannot accept new uploads. Reopen it first." }, { status: 403 });
    }

    const ramDir = await getRamDir();
    fs.mkdirSync(ramDir, { recursive: true });

    // Best-effort disk-space pre-check — reject up front rather than
    // discovering ENOSPC deep into a multi-GB upload. Not fatal if statfs
    // itself fails (e.g. an unsupported filesystem type) — proceed and let
    // the actual writes surface any real problem.
    try {
      const stats = await fs.promises.statfs(ramDir);
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

    const sessionId = crypto.randomUUID();
    const storagePath = path.join(ramDir, `${sessionId}.partial`);
    fs.closeSync(fs.openSync(storagePath, "w"));

    const chunkSize = await getRamChunkSize();

    await prisma.ramUploadSession.create({
      data: {
        id: sessionId,
        filename,
        totalBytes,
        osType,
        hostname: typeof body.hostname === "string" && body.hostname ? body.hostname : null,
        assetName: typeof body.assetName === "string" && body.assetName ? body.assetName : null,
        ipAddress: typeof body.ipAddress === "string" && body.ipAddress ? body.ipAddress : null,
        notes: typeof body.notes === "string" && body.notes ? body.notes : null,
        storagePath,
        uploadedById: actor.id,
        organizationId: actor.organizationIds[0] ?? null,
        caseId,
        expiresAt: new Date(Date.now() + SESSION_TTL_MS),
      },
    });

    registerNewHash(sessionId);

    return NextResponse.json({ sessionId, chunkSize, maxBytes }, { status: 201 });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[ram-analysis/chunked/init] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
