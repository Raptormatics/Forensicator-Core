/**
 * DELETE /api/settings/ai/models/[model] — removes a previously-pulled
 * model from the configured Ollama host. [model] must be URL-encoded by
 * the caller (model names contain ":", e.g. "mistral:7b-instruct").
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { getAiConfig } from "@/lib/settings/system";
import { ollamaDeleteModel, OllamaError } from "@/lib/ai/ollama";
import { prisma } from "@/lib/db/prisma";

export async function DELETE(req: NextRequest, props: { params: Promise<{ model: string }> }) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }


  const model = decodeURIComponent(params.model);
  const { host } = await getAiConfig();

  try {
    await ollamaDeleteModel(host, model);
  } catch (err) {
    const message = err instanceof OllamaError ? err.message : "Failed to delete model.";
    return NextResponse.json({ error: message }, { status: 502 });
  }

  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "ai_model_deleted",
      resourceType: "system_settings", resourceId: "singleton",
      metadata: { model } as object,
      severity: "warning",
    },
  });

  return NextResponse.json({ deleted: true, model });
}
