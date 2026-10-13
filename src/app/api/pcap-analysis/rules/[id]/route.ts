export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { z } from "zod";

// Built-in rules stay read-only even for Core's sole user — only `enabled`
// may be toggled on them. Custom rules (isBuiltin: false) can have any of
// these fields edited.
const CONTENT_FIELDS = ["name", "description", "severity", "logic", "conditions", "tags"] as const;

const UpdateSchema = z.object({
  name:        z.string().min(1).optional(),
  description: z.string().nullable().optional(),
  severity:    z.string().optional(),
  enabled:     z.boolean().optional(),
  logic:       z.string().optional(),
  conditions:  z.array(z.unknown()).min(1).optional(),
  tags:        z.array(z.string()).optional(),
});

// ── GET /api/pcap-analysis/rules/[id] ───────────────────────────────────────
export async function GET(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);

    const rule = await prisma.pcapAnalysisRule.findUnique({
      where: { id: params.id },
      include: { createdBy: { select: { email: true, name: true } } },
    });
    if (!rule) return NextResponse.json({ error: "not_found" }, { status: 404 });

    if (!rule.isBuiltin) {
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

// ── PATCH /api/pcap-analysis/rules/[id] ─────────────────────────────────────
export async function PATCH(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);
    const body  = await req.json();
    const input = UpdateSchema.parse(body);

    const existing = await prisma.pcapAnalysisRule.findUnique({ where: { id: params.id } });
    if (!existing) return NextResponse.json({ error: "not_found" }, { status: 404 });

    if (existing.isBuiltin && CONTENT_FIELDS.some((f) => input[f] !== undefined)) {
      return NextResponse.json({
        error: "builtin_readonly",
        message: "Built-in rule content is read-only. Toggling `enabled` is the only change available on a built-in.",
      }, { status: 403 });
    }

    if (!existing.isBuiltin) {
      if (!existing.organizationId || !actor.organizationIds.includes(existing.organizationId)) {
        return NextResponse.json({ error: "forbidden" }, { status: 403 });
      }
    }

    const data: Record<string, unknown> = {};
    if (input.name        !== undefined) data.name        = input.name.trim();
    if (input.description !== undefined) data.description = input.description;
    if (input.severity    !== undefined) data.severity    = input.severity;
    if (input.enabled     !== undefined) data.enabled     = input.enabled;
    if (input.logic       !== undefined) data.logic       = input.logic.toUpperCase();
    if (input.conditions  !== undefined) data.conditions  = input.conditions;
    if (input.tags        !== undefined) data.tags        = input.tags;

    const rule = await prisma.pcapAnalysisRule.update({
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

// ── DELETE /api/pcap-analysis/rules/[id] ────────────────────────────────────
export async function DELETE(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);

    const existing = await prisma.pcapAnalysisRule.findUnique({ where: { id: params.id } });
    if (!existing) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Deleting a built-in is unrestricted — it's restored the next time
    // "Seed Built-ins" is run.
    if (!existing.isBuiltin) {
      if (!existing.organizationId || !actor.organizationIds.includes(existing.organizationId)) {
        return NextResponse.json({ error: "forbidden" }, { status: 403 });
      }
    }

    await prisma.pcapAnalysisRule.delete({ where: { id: params.id } });

    return NextResponse.json({ success: true });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
