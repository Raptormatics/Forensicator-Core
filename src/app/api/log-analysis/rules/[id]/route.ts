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

const UpdateSchema = z.object({
  name:           z.string().min(1).optional(),
  description:    z.string().nullable().optional(),
  severity:       z.string().optional(),
  enabled:        z.boolean().optional(),
  logic:          z.enum(["AND", "OR"]).optional(),
  conditions:     z.array(ConditionSchema).min(1).optional(),
  tags:           z.array(z.string()).optional(),
  organizationId: z.string().uuid().optional().nullable(),
});

// Fields that change a rule's detection content/identity. Built-in rules
// are read-only on these for everyone — see src/prisma/schema/log-analysis.prisma.
const CONTENT_FIELDS = ["name", "description", "severity", "logic", "conditions", "tags"] as const;

// ── GET /api/log-analysis/rules/[id] ────────────────────────────────────────
export async function GET(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);

    const rule = await prisma.logAnalysisRule.findUnique({
      where: { id: params.id },
      include: { createdBy: { select: { email: true, name: true } } },
    });
    if (!rule) return NextResponse.json({ error: "not_found" }, { status: 404 });

    if (actor.role !== "platform_admin" && !rule.isBuiltin) {
      if (!rule.organizationId || !actor.organizationIds.includes(rule.organizationId)) {
        return NextResponse.json({ error: "forbidden" }, { status: 403 });
      }
    }

    return NextResponse.json({ rule });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── PATCH /api/log-analysis/rules/[id] ──────────────────────────────────────
export async function PATCH(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);
    const body  = await req.json();
    const input = UpdateSchema.parse(body);

    const existing = await prisma.logAnalysisRule.findUnique({ where: { id: params.id } });
    if (!existing) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Built-in rules: content is read-only for everyone, including
    // platform_admin — only `enabled` may be toggled. Custom authoring
    // (which built-ins would require to edit) stays Enterprise-only.
    if (existing.isBuiltin && CONTENT_FIELDS.some((f) => input[f] !== undefined)) {
      return NextResponse.json({ error: "builtin_readonly" }, { status: 403 });
    }

    if (actor.role !== "platform_admin" && !existing.isBuiltin) {
      if (!existing.organizationId || !actor.organizationIds.includes(existing.organizationId)) {
        return NextResponse.json({ error: "forbidden" }, { status: 403 });
      }
    }

    const data: Record<string, unknown> = {};
    if (input.name            !== undefined) data.name            = input.name.trim();
    if (input.description     !== undefined) data.description     = input.description;
    if (input.severity        !== undefined) data.severity        = input.severity;
    if (input.enabled         !== undefined) data.enabled         = input.enabled;
    if (input.logic           !== undefined) data.logic           = input.logic;
    if (input.conditions      !== undefined) data.conditions      = input.conditions;
    if (input.tags            !== undefined) data.tags            = input.tags;
    if (input.organizationId  !== undefined) data.organizationId  = input.organizationId;

    const rule = await prisma.logAnalysisRule.update({
      where: { id: params.id },
      data,
      include: { createdBy: { select: { email: true, name: true } } },
    });

    return NextResponse.json({ rule });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    if (err instanceof z.ZodError) return NextResponse.json({ error: "validation", detail: err.errors }, { status: 422 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── DELETE /api/log-analysis/rules/[id] ─────────────────────────────────────
export async function DELETE(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);

    const existing = await prisma.logAnalysisRule.findUnique({ where: { id: params.id } });
    if (!existing) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Built-in rules can only be removed by a platform_admin. They will be
    // restored the next time "Seed Built-ins" is run.
    if (existing.isBuiltin && actor.role !== "platform_admin") {
      return NextResponse.json({ error: "cannot_delete_builtin" }, { status: 403 });
    }

    if (actor.role !== "platform_admin" && !existing.isBuiltin) {
      if (!existing.organizationId || !actor.organizationIds.includes(existing.organizationId)) {
        return NextResponse.json({ error: "forbidden" }, { status: 403 });
      }
    }

    await prisma.logAnalysisRule.delete({ where: { id: params.id } });

    return NextResponse.json({ success: true });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
