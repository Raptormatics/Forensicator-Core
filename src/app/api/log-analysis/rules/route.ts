export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";

// ── GET /api/log-analysis/rules ─────────────────────────────────────────────
export async function GET(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    const { searchParams } = new URL(req.url);
    const builtinOnly = searchParams.get("builtin") === "true";
    const customOnly  = searchParams.get("custom")  === "true";

    const where: Record<string, unknown> = {};
    if (builtinOnly) where.isBuiltin = true;
    if (customOnly)  where.isBuiltin = false;

    // Everyone sees their org's custom rules + all built-ins (Core has
    // exactly one org, so this isn't really a restriction).
    where.OR = [
      { isBuiltin: true },
      { organizationId: { in: actor.organizationIds } },
    ];

    const rules = await prisma.logAnalysisRule.findMany({
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

// ── POST /api/log-analysis/rules ────────────────────────────────────────────
// Creates a custom rule, scoped to the actor's own organization. Built-in
// rules are never created through this route — they only come from the
// seed endpoint.
export async function POST(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    const body  = await req.json() as Record<string, unknown>;

    const { name, description, severity, enabled, logic, conditions, tags, organizationId } = body;

    if (!name || typeof name !== "string" || !name.trim()) {
      return NextResponse.json({ error: "validation", message: "name is required" }, { status: 400 });
    }
    if (!Array.isArray(conditions) || conditions.length === 0) {
      return NextResponse.json({ error: "validation", message: "At least one condition is required" }, { status: 400 });
    }

    const rule = await prisma.logAnalysisRule.create({
      data: {
        name:          String(name).trim(),
        description:   description ? String(description) : null,
        severity:      String(severity ?? "medium"),
        enabled:       enabled !== false,
        logic:         String(logic ?? "AND").toUpperCase(),
        conditions:    conditions,
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
