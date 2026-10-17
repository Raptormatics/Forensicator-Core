/**
 * PUT /api/ram-analysis/uploads/chunked/[sessionId]/chunk?offset=<bytes>
 * Accepts one raw-binary chunk of a chunked RAM upload session. See
 * src/lib/shared/chunked-upload-state.ts for the concurrency model.
 */
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { getRamChunkSize } from "@/lib/settings/system";
import { withSessionLock, getOrRebuildHash } from "@/lib/shared/chunked-upload-state";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Small fixed allowance above the configured chunk size — the client should
// never exceed it, but multipart/HTTP framing overhead in some clients can
// add a few bytes; this is not meant to be a generous margin.
const OVERHEAD_ALLOWANCE_BYTES = 4096;

type Params = { params: Promise<{ sessionId: string }> };

export async function PUT(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    const actor = await requireAuth(req);
    const { sessionId } = params;

    const offsetParam = req.nextUrl.searchParams.get("offset");
    if (offsetParam === null) {
      return NextResponse.json({ error: "missing_offset", message: "offset query param is required." }, { status: 400 });
    }
    let offset: bigint;
    try {
      offset = BigInt(offsetParam);
    } catch {
      return NextResponse.json({ error: "invalid_offset", message: "offset must be a non-negative integer." }, { status: 400 });
    }

    const chunkSize = await getRamChunkSize();
    const contentLengthHeader = req.headers.get("content-length");
    const contentLength = contentLengthHeader ? Number(contentLengthHeader) : NaN;
    if (!Number.isFinite(contentLength) || contentLength <= 0) {
      return NextResponse.json({ error: "missing_content_length", message: "Content-Length header is required." }, { status: 411 });
    }
    if (contentLength > chunkSize + OVERHEAD_ALLOWANCE_BYTES) {
      return NextResponse.json({ error: "chunk_too_large", message: `Each chunk must be at most ${chunkSize} bytes.` }, { status: 413 });
    }

    const session = await prisma.ramUploadSession.findUnique({ where: { id: sessionId } });
    if (!session || session.uploadedById !== actor.id) {
      return NextResponse.json({ error: "not_found" }, { status: 404 });
    }
    if (session.status !== "uploading") {
      return NextResponse.json({ error: "session_not_active", message: `This upload session is already ${session.status}.` }, { status: 409 });
    }
    if (session.expiresAt.getTime() < Date.now()) {
      return NextResponse.json({ error: "session_expired", message: "This upload session has expired. Start a new upload." }, { status: 410 });
    }

    const buffer = Buffer.from(await req.arrayBuffer());

    const result = await withSessionLock(sessionId, async () => {
      // Re-check inside the lock — another chunk request for this session
      // may have already advanced receivedBytes while we were waiting.
      const fresh = await prisma.ramUploadSession.findUnique({ where: { id: sessionId } });
      if (!fresh || fresh.status !== "uploading") {
        return { error: "session_not_active" as const, message: `This upload session is already ${fresh?.status ?? "gone"}.` };
      }
      if (offset !== fresh.receivedBytes) {
        return { error: "offset_mismatch" as const, expectedOffset: fresh.receivedBytes };
      }

      const hash = await getOrRebuildHash(sessionId, fresh.storagePath, fresh.receivedBytes);

      const fh = await fs.promises.open(fresh.storagePath, "r+");
      try {
        await fh.write(buffer, 0, buffer.length, Number(offset));
      } finally {
        await fh.close();
      }
      hash.update(buffer);

      const newReceivedBytes = fresh.receivedBytes + BigInt(buffer.length);
      const updated = await prisma.ramUploadSession.update({
        where: { id: sessionId },
        data: { receivedBytes: newReceivedBytes },
        select: { receivedBytes: true, totalBytes: true },
      });

      return { ok: true as const, receivedBytes: updated.receivedBytes, totalBytes: updated.totalBytes };
    });

    if ("error" in result) {
      if (result.error === "offset_mismatch") {
        return NextResponse.json(
          { error: "offset_mismatch", expectedOffset: result.expectedOffset.toString() },
          { status: 409 }
        );
      }
      return NextResponse.json({ error: result.error, message: result.message }, { status: 409 });
    }

    return NextResponse.json({
      receivedBytes: result.receivedBytes.toString(),
      totalBytes: result.totalBytes.toString(),
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[ram-analysis/chunked/chunk] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
