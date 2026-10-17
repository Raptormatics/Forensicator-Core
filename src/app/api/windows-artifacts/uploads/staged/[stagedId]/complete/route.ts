/**
 * POST /api/windows-artifacts/uploads/staged/[stagedId]/complete — marks a
 * chunked Windows Artifact file upload as fully received. Unlike RAM's
 * equivalent route, this does NOT create a final DB row or move the file
 * into permanent storage yet — a staged file isn't tied to a role/upload/
 * case until the main /api/windows-artifacts/uploads POST consumes it by
 * stagedId (which may bundle several other files alongside it). This just
 * flips status to "staged" so that consuming route can find it.
 */
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { withSessionLock, deleteSessionState } from "@/lib/shared/chunked-upload-state";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Params = { params: Promise<{ stagedId: string }> };

export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    const actor = await requireAuth(req);
    const { stagedId } = params;

    const result = await withSessionLock(stagedId, async () => {
      const staged = await prisma.windowsArtifactStagedFile.findUnique({ where: { id: stagedId } });
      if (!staged || staged.uploadedById !== actor.id) {
        return { error: "not_found" as const };
      }
      if (staged.status !== "uploading") {
        return { error: "session_not_active" as const, message: `This upload is already ${staged.status}.` };
      }
      if (staged.receivedBytes !== staged.totalBytes) {
        return {
          error: "incomplete" as const,
          message: "Not all bytes have been uploaded yet.",
          receivedBytes: staged.receivedBytes,
          totalBytes: staged.totalBytes,
        };
      }

      // Defense-in-depth: verify the bytes actually on disk match the
      // counter, independent of whatever the DB says.
      const stat = await fs.promises.stat(staged.storagePath).catch(() => null);
      if (!stat || BigInt(stat.size) !== staged.totalBytes) {
        return { error: "size_mismatch" as const, message: "The uploaded file's size on disk does not match the expected total." };
      }

      await prisma.windowsArtifactStagedFile.update({ where: { id: stagedId }, data: { status: "staged" } });
      deleteSessionState(stagedId);

      return { ok: true as const };
    });

    if ("error" in result) {
      const status =
        result.error === "not_found" ? 404 :
        result.error === "incomplete" ? 400 : 409;
      const body: Record<string, unknown> = { error: result.error, message: "message" in result ? result.message : undefined };
      if (result.error === "incomplete") {
        body.receivedBytes = result.receivedBytes.toString();
        body.totalBytes = result.totalBytes.toString();
      }
      return NextResponse.json(body, { status });
    }

    return NextResponse.json({ stagedId }, { status: 200 });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[windows-artifacts/staged/complete] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
