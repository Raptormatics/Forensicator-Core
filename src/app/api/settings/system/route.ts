export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";

const SINGLETON_ID = "singleton";

// GET — any authenticated user. Neither field here is sensitive (a public
// URL, a directory path), and every user benefits from the API docs
// showing the right base URL, not just admins. AI provider config lives at
// /api/settings/ai (see Settings > AI Analysis) — it has its own encrypted
// API key field, which doesn't belong on this general-purpose route.
export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const settings = await prisma.systemSettings.findUnique({ where: { id: SINGLETON_ID } });
  return NextResponse.json({
    appDomain: settings?.appDomain ?? null,
    reportsDir: settings?.reportsDir ?? null,
    pcapDir: settings?.pcapDir ?? null,
    tsharkPath: settings?.tsharkPath ?? null,
    ramDir: settings?.ramDir ?? null,
    volatilityPath: settings?.volatilityPath ?? null,
    volatilitySymbolsDir: settings?.volatilitySymbolsDir ?? null,
    ramChunkSizeBytes: settings?.ramChunkSizeBytes ?? null,
    winArtifactsDir: settings?.winArtifactsDir ?? null,
    winArtifactsPythonPath: settings?.winArtifactsPythonPath ?? null,
    winArtifactsBitsPythonPath: settings?.winArtifactsBitsPythonPath ?? null,
    winArtifactsMaxUploadBytes: settings?.winArtifactsMaxUploadBytes != null ? Number(settings.winArtifactsMaxUploadBytes) : null,
  });
}

const putSchema = z.object({
  // Empty string clears the setting (falls back to auto-detection) —
  // distinct from omitting the field, which leaves it unchanged.
  appDomain: z.union([z.string().url().max(255), z.literal("")]).optional(),
  reportsDir: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
  pcapDir: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
  tsharkPath: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
  ramDir: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
  volatilityPath: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
  volatilitySymbolsDir: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
  // 0 clears the override (falls back to env var / 40MB default) — distinct
  // from omitting the field, which leaves it unchanged.
  ramChunkSizeBytes: z.number().int().min(0).optional(),
  winArtifactsDir: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
  winArtifactsPythonPath: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
  winArtifactsBitsPythonPath: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
  // 0 clears the override (falls back to env var / 5GB default) — same
  // convention as ramChunkSizeBytes above.
  winArtifactsMaxUploadBytes: z.number().int().min(0).optional(),
});

// PUT — unrestricted (Core's sole user).
export async function PUT(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }


  let body;
  try {
    body = putSchema.parse(await req.json());
  } catch (e) {
    if (e instanceof z.ZodError) return NextResponse.json({ error: e.errors[0].message }, { status: 400 });
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const data: {
    appDomain?: string | null; reportsDir?: string | null; pcapDir?: string | null; tsharkPath?: string | null;
    ramDir?: string | null; volatilityPath?: string | null; volatilitySymbolsDir?: string | null; ramChunkSizeBytes?: number | null;
    winArtifactsDir?: string | null; winArtifactsPythonPath?: string | null; winArtifactsBitsPythonPath?: string | null;
    winArtifactsMaxUploadBytes?: bigint | null;
  } = {};
  if (body.appDomain !== undefined) {
    // Strip a trailing slash so callers can safely do `${appDomain}/api` etc.
    data.appDomain = body.appDomain === "" ? null : body.appDomain.replace(/\/+$/, "");
  }
  if (body.reportsDir !== undefined) {
    data.reportsDir = body.reportsDir === "" ? null : body.reportsDir.trim();
  }
  if (body.pcapDir !== undefined) {
    data.pcapDir = body.pcapDir === "" ? null : body.pcapDir.trim();
  }
  if (body.tsharkPath !== undefined) {
    data.tsharkPath = body.tsharkPath === "" ? null : body.tsharkPath.trim();
  }
  if (body.ramDir !== undefined) {
    data.ramDir = body.ramDir === "" ? null : body.ramDir.trim();
  }
  if (body.volatilityPath !== undefined) {
    data.volatilityPath = body.volatilityPath === "" ? null : body.volatilityPath.trim();
  }
  if (body.volatilitySymbolsDir !== undefined) {
    data.volatilitySymbolsDir = body.volatilitySymbolsDir === "" ? null : body.volatilitySymbolsDir.trim();
  }
  if (body.ramChunkSizeBytes !== undefined) {
    data.ramChunkSizeBytes = body.ramChunkSizeBytes === 0 ? null : body.ramChunkSizeBytes;
  }
  if (body.winArtifactsDir !== undefined) {
    data.winArtifactsDir = body.winArtifactsDir === "" ? null : body.winArtifactsDir.trim();
  }
  if (body.winArtifactsPythonPath !== undefined) {
    data.winArtifactsPythonPath = body.winArtifactsPythonPath === "" ? null : body.winArtifactsPythonPath.trim();
  }
  if (body.winArtifactsBitsPythonPath !== undefined) {
    data.winArtifactsBitsPythonPath = body.winArtifactsBitsPythonPath === "" ? null : body.winArtifactsBitsPythonPath.trim();
  }
  if (body.winArtifactsMaxUploadBytes !== undefined) {
    data.winArtifactsMaxUploadBytes = body.winArtifactsMaxUploadBytes === 0 ? null : BigInt(body.winArtifactsMaxUploadBytes);
  }

  const settings = await prisma.systemSettings.upsert({
    where: { id: SINGLETON_ID },
    update: data,
    create: { id: SINGLETON_ID, ...data },
  });

  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email,
      action: "system_settings_updated",
      resourceType: "system_settings", resourceId: SINGLETON_ID,
      // metadata is a Prisma Json field — bigint (winArtifactsMaxUploadBytes)
      // isn't JSON-serializable, so it's narrowed to a number here first.
      metadata: { ...data, winArtifactsMaxUploadBytes: data.winArtifactsMaxUploadBytes != null ? Number(data.winArtifactsMaxUploadBytes) : data.winArtifactsMaxUploadBytes } as object,
      severity: "warning",
    },
  });

  return NextResponse.json({
    appDomain: settings.appDomain,
    reportsDir: settings.reportsDir,
    pcapDir: settings.pcapDir,
    tsharkPath: settings.tsharkPath,
    ramDir: settings.ramDir,
    volatilityPath: settings.volatilityPath,
    volatilitySymbolsDir: settings.volatilitySymbolsDir,
    ramChunkSizeBytes: settings.ramChunkSizeBytes,
    winArtifactsDir: settings.winArtifactsDir,
    winArtifactsPythonPath: settings.winArtifactsPythonPath,
    winArtifactsBitsPythonPath: settings.winArtifactsBitsPythonPath,
    winArtifactsMaxUploadBytes: settings.winArtifactsMaxUploadBytes != null ? Number(settings.winArtifactsMaxUploadBytes) : null,
  });
}
