/**
 * GET  /api/settings/ai/models — list models pulled on the configured
 *      Ollama host, plus any pull currently in progress.
 * POST /api/settings/ai/models — start pulling a model (fire-and-forget;
 *      progress is polled via the GET above).
 *
 * Ollama-specific: model pull/list/delete has no equivalent for hosted
 * commercial APIs (openai/anthropic/azure_openai) — the Settings page only
 * renders this section when aiProvider is "ollama".
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { getAiConfig } from "@/lib/settings/system";
import { ollamaListModels, OllamaError } from "@/lib/ai/ollama";
import { startModelPull, currentPullStatus, isPulling } from "@/lib/ai/model-pull";

export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const { host } = await getAiConfig();
  let models: Awaited<ReturnType<typeof ollamaListModels>> = [];
  let error: string | null = null;
  try {
    models = await ollamaListModels(host);
  } catch (err) {
    error = err instanceof OllamaError ? err.message : "Could not reach Ollama.";
  }

  return NextResponse.json({ models, error, pull: currentPullStatus() });
}

const postSchema = z.object({ model: z.string().min(1).max(200) });

export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const { model } = postSchema.parse(await req.json());

  if (isPulling()) {
    return NextResponse.json({ error: "A model pull is already in progress." }, { status: 409 });
  }

  const { host } = await getAiConfig();
  try {
    startModelPull(host, model);
  } catch (err) {
    return NextResponse.json({ error: err instanceof Error ? err.message : "Failed to start pull." }, { status: 409 });
  }

  await import("@/lib/db/prisma").then(({ prisma }) =>
    prisma.auditLog.create({
      data: {
        actorId: actor.id, actorEmail: actor.email,
        action: "ai_model_pull_started",
        resourceType: "system_settings", resourceId: "singleton",
        metadata: { model } as object,
        severity: "info",
      },
    })
  );

  return NextResponse.json({ started: true, model }, { status: 202 });
}
