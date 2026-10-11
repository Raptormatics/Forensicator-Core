export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";

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
  });
}

const putSchema = z.object({
  // Empty string clears the setting (falls back to auto-detection) —
  // distinct from omitting the field, which leaves it unchanged.
  appDomain: z.union([z.string().url().max(255), z.literal("")]).optional(),
  reportsDir: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
  pcapDir: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
  tsharkPath: z.union([z.string().min(1).max(500), z.literal("")]).optional(),
});

// PUT — instance admin only (platform_admin, or org_admin in appliance
// mode — see isInstanceAdmin). Same tier as managing platform updates:
// this affects the whole shared instance, not just one org.
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

  const data: { appDomain?: string | null; reportsDir?: string | null; pcapDir?: string | null; tsharkPath?: string | null } = {};
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
      metadata: data as object,
      severity: "warning",
    },
  });

  return NextResponse.json({
    appDomain: settings.appDomain,
    reportsDir: settings.reportsDir,
    pcapDir: settings.pcapDir,
    tsharkPath: settings.tsharkPath,
  });
}
