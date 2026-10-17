/**
 * DELETE /api/ram-analysis/uploads/chunked/[sessionId] — explicit cancel of
 * an in-progress chunked RAM upload. Abandoned sessions that are never
 * explicitly cancelled are eventually swept by the periodic cleanup job
 * (src/lib/jobs/ram-session-cleanup-worker.ts); this just does it
 * immediately instead of waiting up to 24h.
 */
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { withSessionLock, deleteSessionState } from "@/lib/shared/chunked-upload-state";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Params = { params: Promise<{ sessionId: string }> };

export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    const actor = await requireAuth(req);
    const { sessionId } = params;

    await withSessionLock(sessionId, async () => {
      const session = await prisma.ramUploadSession.findUnique({ where: { id: sessionId } });
      if (!session || session.uploadedById !== actor.id) return;

      await fs.promises.unlink(session.storagePath).catch(() => {});
      await prisma.ramUploadSession.delete({ where: { id: sessionId } }).catch(() => {});
      deleteSessionState(sessionId);
    });

    return NextResponse.json({ ok: true });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[ram-analysis/chunked/delete] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
