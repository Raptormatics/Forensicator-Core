/**
 * POST /api/settings/ai/test — sends a trivial prompt through the currently
 * SAVED provider config (or an optional override in the request body, so
 * the Settings page can "Test Connection" before hitting Save) and reports
 * whether it got a real completion back.
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { getAiConfig } from "@/lib/settings/system";
import { testAiProviderConnection, type AiProvider } from "@/lib/ai/provider";

const PROVIDERS = ["ollama", "openai", "openai_compatible", "azure_openai", "anthropic"] as const;

const bodySchema = z.object({
  provider: z.enum(PROVIDERS).optional(),
  host: z.string().max(500).optional(),
  model: z.string().max(200).optional(),
  apiKey: z.string().max(500).optional(),
});

export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const override = bodySchema.parse(await req.json().catch(() => ({})));
  const saved = await getAiConfig();

  const config = {
    provider: (override.provider ?? saved.provider) as AiProvider,
    host: override.host ?? saved.host,
    model: override.model ?? saved.model,
    // A blank apiKey in the override means "use the saved one", not "no key" —
    // the Settings form never shows the real key back, so it can't send it
    // as an override unless the admin just typed a new one.
    apiKey: override.apiKey || saved.apiKey,
  };

  const result = await testAiProviderConnection(config);
  return NextResponse.json(result);
}
