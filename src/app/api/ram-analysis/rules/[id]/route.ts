export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * PATCH here only ever accepts `enabled` — editing a rule's actual
 * detection content (name/description/severity/logic/conditions/tags) is
 * custom-rule *authoring*, an Enterprise-only capability, and that code
 * doesn't exist in this file at all (not a check gating otherwise-working
 * logic — Core is open source, so that would be trivially bypassable).
 * The Enterprise overlay replaces this file with a version that can edit
 * any field (see that file's own header comment).
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { z } from "zod";

const UpdateSchema = z.object({
  enabled: z.boolean(),
});

// ── GET /api/ram-analysis/rules/[id] ────────────────────────────────────────
export async function GET(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);

    const rule = await prisma.ramAnalysisRule.findUnique({
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

// ── PATCH /api/ram-analysis/rules/[id] ──────────────────────────────────────
export async function PATCH(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);
    const body  = await req.json();

    const requestedFields = Object.keys(body ?? {});
    if (requestedFields.some((f) => f !== "enabled")) {
      return NextResponse.json({
        error: "enterprise_feature",
        message: "Editing rule content requires Enterprise. Toggling `enabled` is the only change available in Core.",
      }, { status: 403 });
    }

    const input = UpdateSchema.parse(body);

    const existing = await prisma.ramAnalysisRule.findUnique({ where: { id: params.id } });
    if (!existing) return NextResponse.json({ error: "not_found" }, { status: 404 });

    if (actor.role !== "platform_admin" && !existing.isBuiltin) {
      if (!existing.organizationId || !actor.organizationIds.includes(existing.organizationId)) {
        return NextResponse.json({ error: "forbidden" }, { status: 403 });
      }
    }

    const rule = await prisma.ramAnalysisRule.update({
      where: { id: params.id },
      data: { enabled: input.enabled },
      include: { createdBy: { select: { email: true, name: true } } },
    });

    return NextResponse.json({ rule });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    if (err instanceof z.ZodError) return NextResponse.json({ error: "validation", detail: err.errors }, { status: 422 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── DELETE /api/ram-analysis/rules/[id] ─────────────────────────────────────
export async function DELETE(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);

    const existing = await prisma.ramAnalysisRule.findUnique({ where: { id: params.id } });
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

    await prisma.ramAnalysisRule.delete({ where: { id: params.id } });

    return NextResponse.json({ success: true });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
