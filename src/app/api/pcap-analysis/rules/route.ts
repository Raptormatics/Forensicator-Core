export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { z } from "zod";

const ConditionSchema = z.object({
  id:       z.string(),
  field:    z.string(),
  operator: z.string(),
  value:    z.string(),
});

const CreateSchema = z.object({
  name:           z.string().min(1),
  description:    z.string().nullable().optional(),
  severity:       z.string().optional(),
  enabled:        z.boolean().optional(),
  logic:          z.enum(["AND", "OR"]).optional(),
  conditions:     z.array(ConditionSchema).min(1),
  tags:           z.array(z.string()).optional(),
  organizationId: z.string().uuid().optional().nullable(),
  isBuiltin:      z.boolean().optional(),
});

// ── GET /api/pcap-analysis/rules ────────────────────────────────────────────
export async function GET(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    const { searchParams } = new URL(req.url);
    const builtinOnly = searchParams.get("builtin") === "true";
    const customOnly  = searchParams.get("custom")  === "true";

    const where: Record<string, unknown> = {};
    if (builtinOnly) where.isBuiltin = true;
    if (customOnly)  where.isBuiltin = false;

    // Non-admin users see only their org's custom rules + all built-ins
    if (actor.role !== "platform_admin") {
      where.OR = [
        { isBuiltin: true },
        { organizationId: { in: actor.organizationIds } },
      ];
    }

    const rules = await prisma.pcapAnalysisRule.findMany({
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

// ── POST /api/pcap-analysis/rules ───────────────────────────────────────────
export async function POST(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    const body  = await req.json();
    const input = CreateSchema.parse(body);

    const rule = await prisma.pcapAnalysisRule.create({
      data: {
        name:           input.name.trim(),
        description:    input.description ?? null,
        severity:       input.severity ?? "medium",
        enabled:        input.enabled !== false,
        isBuiltin:      actor.role === "platform_admin" && (input.isBuiltin ?? false),
        logic:          input.logic ?? "AND",
        conditions:     input.conditions,
        tags:           input.tags ?? [],
        createdById:    actor.id,
        organizationId: input.organizationId ?? actor.organizationIds[0] ?? null,
      },
      include: { createdBy: { select: { email: true, name: true } } },
    });

    return NextResponse.json({ rule }, { status: 201 });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    if (err instanceof z.ZodError) return NextResponse.json({ error: "validation", detail: err.errors }, { status: 422 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
