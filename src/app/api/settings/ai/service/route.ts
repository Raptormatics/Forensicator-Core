/**
 * GET  /api/settings/ai/service — status of the locally-managed Ollama
 *      systemd service (installed?, active?, version, in-flight progress).
 * POST /api/settings/ai/service — {action: "install"|"uninstall"|"start"|"stop"}
 *      kicks off deploy/forensicator-ollama-ctl.sh via the scoped sudoers
 *      rule; progress is polled via the GET above (same convention as
 *      /api/admin/updates/status).
 *
 * Only meaningful when SystemSettings.ollamaManaged is true — the Settings
 * page only shows these controls in that mode.
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { prisma } from "@/lib/db/prisma";
import { ollamaProgress, ollamaLastResult, startOllamaCtl, getOllamaCtlStatus } from "@/lib/ai/ollama-service";

export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const progress = ollamaProgress();
  // Skip the sudo status round-trip while an install/uninstall is actively
  // running — it's slower and the progress file already tells the UI what
  // it needs; only check real systemctl state when nothing is in flight.
  const status = progress ? { installed: false, active: "unknown", version: null } : await getOllamaCtlStatus();

  return NextResponse.json({
    progress,
    lastResult: ollamaLastResult(),
    ...status,
  });
}

const ACTIONS = ["install", "uninstall", "start", "stop"] as const;
const postSchema = z.object({
  action: z.enum(ACTIONS),
  purgeModels: z.boolean().optional(),
});

export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const { action, purgeModels } = postSchema.parse(await req.json());

  if (ollamaProgress()) {
    return NextResponse.json({ error: "An Ollama service action is already in progress." }, { status: 409 });
  }

  startOllamaCtl(action, { purgeModels });

  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: `ai_ollama_service_${action}`,
      resourceType: "system_settings", resourceId: "singleton",
      metadata: { action, purgeModels: !!purgeModels } as object,
      severity: "warning",
    },
  });

  return NextResponse.json({ started: true, action }, { status: 202 });
}
