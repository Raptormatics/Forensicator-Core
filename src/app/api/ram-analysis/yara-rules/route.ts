export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { getVolatilityPath } from "@/lib/settings/system";
import { validateYaraSource } from "@/lib/ram-analysis/yara";

// ── GET /api/ram-analysis/yara-rules ────────────────────────────────────────
export async function GET(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    const { searchParams } = new URL(req.url);
    const builtinOnly = searchParams.get("builtin") === "true";
    const customOnly  = searchParams.get("custom")  === "true";

    const where: Record<string, unknown> = {};
    if (builtinOnly) where.isBuiltin = true;
    if (customOnly)  where.isBuiltin = false;

    if (actor.role !== "platform_admin") {
      where.OR = [
        { isBuiltin: true },
        { organizationId: { in: actor.organizationIds } },
      ];
    }

    const rules = await prisma.ramYaraRule.findMany({
      where,
      orderBy: [{ isBuiltin: "desc" }, { createdAt: "desc" }],
      include: { createdBy: { select: { email: true, name: true } } },
    });

    return NextResponse.json({ rules });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── POST /api/ram-analysis/yara-rules ───────────────────────────────────────
// Creates a custom Yara signature, scoped to the actor's own organization.
// Built-in signatures are never created through this route — they only
// come from the seed endpoint.
export async function POST(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    const body  = await req.json() as Record<string, unknown>;

    const { name, description, severity, enabled, yaraSource, tags, organizationId } = body;

    if (!name || typeof name !== "string" || !name.trim()) {
      return NextResponse.json({ error: "validation", message: "name is required" }, { status: 400 });
    }
    if (!yaraSource || typeof yaraSource !== "string" || !yaraSource.trim()) {
      return NextResponse.json({ error: "validation", message: "Yara source is required" }, { status: 400 });
    }

    const volPath = await getVolatilityPath();
    const validation = await validateYaraSource(volPath, yaraSource);
    if (!validation.valid) {
      return NextResponse.json({ error: "yara_syntax", message: validation.message }, { status: 400 });
    }

    const rule = await prisma.ramYaraRule.create({
      data: {
        name:          String(name).trim(),
        description:   description ? String(description) : null,
        severity:      String(severity ?? "medium"),
        enabled:       enabled !== false,
        yaraSource:    String(yaraSource),
        tags:          Array.isArray(tags) ? tags.map(String) : [],
        createdById:   actor.id,
        organizationId: organizationId
          ? String(organizationId)
          : (actor.organizationIds[0] ?? null),
      },
      include: { createdBy: { select: { email: true, name: true } } },
    });

    return NextResponse.json({ rule }, { status: 201 });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
