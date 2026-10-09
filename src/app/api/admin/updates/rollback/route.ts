export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { UPDATE_SCRIPT, currentProgress, listBackups } from "@/lib/updates/paths";
import { actorIp } from "@/lib/updates/install";

const bodySchema = z.object({ backupId: z.string().min(1) });

// POST — platform_admin, or org_admin in appliance mode (see
// isInstanceAdmin). Restores a prior backup via the same privileged
// script used for installs (--rollback mode), fire-and-forget for the
// same reason as the upload route: it restarts this process.
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

  const { backupId } = bodySchema.parse(await req.json());
  if (!listBackups().some((b) => b.manifest.id === backupId)) {
    return NextResponse.json({ error: "No such backup." }, { status: 404 });
  }

  await prisma.auditLog.create({
    data: {
      actorId: actor.id,
      actorEmail: actor.email,
      actorIp: actorIp(req.headers),
      action: "update_rollback_started",
      resourceType: "system",
      resourceId: backupId,
      result: "success",
      severity: "warning",
      metadata: { backupId } as never,
    },
  });

  const child = spawn("sudo", [UPDATE_SCRIPT, "--rollback", backupId], { detached: true, stdio: "ignore" });
  child.on("error", (err) => console.error("[updates] failed to spawn installer:", err));
  child.unref();

  return NextResponse.json({ started: true }, { status: 202 });
}
