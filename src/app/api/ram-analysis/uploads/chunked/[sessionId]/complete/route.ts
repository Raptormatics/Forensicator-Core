/**
 * POST /api/ram-analysis/uploads/chunked/[sessionId]/complete — finalizes a
 * chunked RAM upload session into a real RamUpload row, exactly matching
 * the legacy single-shot route's success response shape.
 */
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { getRamQueue } from "@/lib/jobs/queues";
import { matchedExtension } from "@/lib/ram-analysis/upload-shared";
import { withSessionLock, getOrRebuildHash, deleteSessionState } from "@/lib/ram-analysis/chunked-upload-state";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Params = { params: Promise<{ sessionId: string }> };

export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    const actor = await requireAuth(req);
    const { sessionId } = params;

    const result = await withSessionLock(sessionId, async () => {
      const session = await prisma.ramUploadSession.findUnique({ where: { id: sessionId } });
      if (!session || session.uploadedById !== actor.id) {
        return { error: "not_found" as const };
      }
      if (session.status !== "uploading") {
        return { error: "session_not_active" as const, message: `This upload session is already ${session.status}.` };
      }
      if (session.receivedBytes !== session.totalBytes) {
        return {
          error: "incomplete" as const,
          message: "Not all bytes have been uploaded yet.",
          receivedBytes: session.receivedBytes,
          totalBytes: session.totalBytes,
        };
      }

      // A chunked session can span minutes to hours — re-validate the case
      // wasn't closed mid-upload rather than trusting the check from /init.
      const kase = await prisma.case.findUnique({ where: { id: session.caseId ?? "" }, select: { id: true, status: true } });
      if (!kase) {
        return { error: "invalid_case" as const, message: "The specified case no longer exists." };
      }
      if (kase.status === "closed") {
        return { error: "case_closed" as const, message: "This case was closed while the upload was in progress." };
      }

      // Defense-in-depth: verify the bytes actually on disk match the
      // counter, independent of whatever the DB says.
      const stat = await fs.promises.stat(session.storagePath).catch(() => null);
      if (!stat || BigInt(stat.size) !== session.totalBytes) {
        return { error: "size_mismatch" as const, message: "The uploaded file's size on disk does not match the expected total." };
      }

      const ext = matchedExtension(session.filename, session.osType) ?? "";
      const finalPath = path.join(path.dirname(session.storagePath), `${sessionId}${ext}`);

      const hash = await getOrRebuildHash(sessionId, session.storagePath, session.receivedBytes);
      const sha256 = hash.digest("hex");

      await fs.promises.rename(session.storagePath, finalPath);

      try {
        const upload = await prisma.ramUpload.create({
          data: {
            id: sessionId,
            filename: session.filename,
            fileSize: session.totalBytes,
            sha256,
            status: "queued",
            storagePath: finalPath,
            osType: session.osType,
            hostname: session.hostname,
            assetName: session.assetName,
            ipAddress: session.ipAddress,
            notes: session.notes,
            uploadedById: session.uploadedById,
            organizationId: session.organizationId,
            caseId: session.caseId,
          },
        });

        const job = await getRamQueue().add("process-ram", { ramUploadId: upload.id });
        const updated = await prisma.ramUpload.update({
          where: { id: upload.id },
          data: { jobId: job.id ?? null },
        });

        await prisma.ramUploadSession.update({ where: { id: sessionId }, data: { status: "completed" } });
        deleteSessionState(sessionId);

        return { ok: true as const, upload: updated };
      } catch (createErr) {
        // Roll back the rename so the file isn't orphaned with no DB row
        // pointing at it — leave the session in a retryable state.
        await fs.promises.rename(finalPath, session.storagePath).catch(() => {});
        console.error("[ram-analysis/chunked/complete] RamUpload create failed, rolled back rename:", createErr);
        return { error: "server_error" as const, message: "Failed to finalize the upload. Please retry." };
      }
    });

    if ("error" in result) {
      const status =
        result.error === "not_found" ? 404 :
        result.error === "incomplete" ? 400 :
        result.error === "case_closed" ? 403 :
        result.error === "invalid_case" ? 400 :
        result.error === "server_error" ? 500 : 409;
      const body: Record<string, unknown> = { error: result.error, message: "message" in result ? result.message : undefined };
      if (result.error === "incomplete") {
        body.receivedBytes = result.receivedBytes.toString();
        body.totalBytes = result.totalBytes.toString();
      }
      return NextResponse.json(body, { status });
    }

    return NextResponse.json(
      { upload: { ...result.upload, fileSize: result.upload.fileSize.toString() } },
      { status: 201 }
    );
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[ram-analysis/chunked/complete] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
