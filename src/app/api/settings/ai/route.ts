export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { encryptSecret } from "@/lib/crypto/secret-box";

const SINGLETON_ID = "singleton";
const PROVIDERS = ["ollama", "openai", "openai_compatible", "azure_openai", "anthropic"] as const;

// GET — any authenticated user. Mirrors /api/settings/system: nothing here
// is sensitive except the API key, which is never returned (only its last
// 4 chars, for display, same as OrgThreatIntelProvider).
export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const settings = await prisma.systemSettings.findUnique({ where: { id: SINGLETON_ID } });
  return NextResponse.json({
    aiEnabled: settings?.aiEnabled ?? false,
    aiProvider: settings?.aiProvider ?? "ollama",
    aiHost: settings?.aiHost ?? "http://localhost:11434",
    aiModel: settings?.aiModel ?? "mistral:7b-instruct",
    aiApiKeyLast4: settings?.aiApiKeyLast4 ?? null,
    hasApiKey: !!settings?.aiApiKeyEncrypted,
    ollamaManaged: settings?.ollamaManaged ?? false,
  });
}

const putSchema = z.object({
  aiEnabled: z.boolean().optional(),
  aiProvider: z.enum(PROVIDERS).optional(),
  aiHost: z.string().max(500).optional(),
  aiModel: z.string().min(1).max(200).optional(),
  // Empty string clears the stored key; omit the field to leave it unchanged.
  apiKey: z.string().max(500).optional(),
  ollamaManaged: z.boolean().optional(),
});

// PUT — instance admin only (platform_admin, or org_admin in appliance mode).
export async function PUT(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  let body;
  try {
    body = putSchema.parse(await req.json());
  } catch (e) {
    if (e instanceof z.ZodError) return NextResponse.json({ error: e.errors[0].message }, { status: 400 });
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const data: Record<string, unknown> = {};
  if (body.aiEnabled !== undefined) data.aiEnabled = body.aiEnabled;
  if (body.aiProvider !== undefined) data.aiProvider = body.aiProvider;
  if (body.aiHost !== undefined) data.aiHost = body.aiHost.trim().replace(/\/+$/, "");
  if (body.aiModel !== undefined) data.aiModel = body.aiModel.trim();
  if (body.ollamaManaged !== undefined) data.ollamaManaged = body.ollamaManaged;
  if (body.apiKey !== undefined) {
    if (body.apiKey === "") {
      data.aiApiKeyEncrypted = null;
      data.aiApiKeyLast4 = null;
    } else {
      data.aiApiKeyEncrypted = encryptSecret(body.apiKey);
      data.aiApiKeyLast4 = body.apiKey.slice(-4);
    }
  }

  const settings = await prisma.systemSettings.upsert({
    where: { id: SINGLETON_ID },
    update: data,
    create: { id: SINGLETON_ID, ...data },
  });

  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "ai_settings_updated",
      resourceType: "system_settings", resourceId: SINGLETON_ID,
      metadata: { ...data, aiApiKeyEncrypted: data.aiApiKeyEncrypted ? "[redacted]" : undefined } as object,
      severity: "warning",
    },
  });

  return NextResponse.json({
    aiEnabled: settings.aiEnabled,
    aiProvider: settings.aiProvider,
    aiHost: settings.aiHost,
    aiModel: settings.aiModel,
    aiApiKeyLast4: settings.aiApiKeyLast4,
    hasApiKey: !!settings.aiApiKeyEncrypted,
    ollamaManaged: settings.ollamaManaged,
  });
}
