export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma }              from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { z }                   from "zod";
import { compileDecoder, loadDecoders } from "@/lib/log-analysis/decoder-engine/engine";

const UpdateSchema = z.object({
  yamlContent:    z.string().min(10).optional(),
  enabled:        z.boolean().optional(),
  organizationId: z.string().uuid().optional().nullable(),
});

// ── GET /api/log-analysis/decoders/[id] ─────────────────────────────────────
export async function GET(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);

    const decoder = await prisma.logDecoder.findUnique({
      where: { id: params.id },
      include: {
        createdBy:    { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
      },
    });

    if (!decoder) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Access check: non-builtin decoders stay scoped to their own org
    if (!decoder.isBuiltin) {
      if (!decoder.organizationId || !actor.organizationIds.includes(decoder.organizationId)) {
        return NextResponse.json({ error: "forbidden" }, { status: 403 });
      }
    }

    return NextResponse.json({ decoder });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── PATCH /api/log-analysis/decoders/[id] ───────────────────────────────────
export async function PATCH(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);
    const body  = await req.json();
    const input = UpdateSchema.parse(body);

    const existing = await prisma.logDecoder.findUnique({ where: { id: params.id } });
    if (!existing) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Access check: non-builtin decoders stay scoped to their own org
    if (!existing.isBuiltin) {
      if (!existing.organizationId || !actor.organizationIds.includes(existing.organizationId)) {
        return NextResponse.json({ error: "forbidden" }, { status: 403 });
      }
    }

    const updateData: Record<string, unknown> = {};

    if (input.yamlContent !== undefined) {
      // Validate new YAML
      let def;
      try {
        def = compileDecoder(input.yamlContent, false);
      } catch (err) {
        return NextResponse.json({ error: "invalid_yaml", detail: String(err) }, { status: 400 });
      }
      updateData.yamlContent  = input.yamlContent;
      updateData.name         = def.name;
      updateData.title        = def.title ?? null;
      updateData.description  = def.description ?? null;
      updateData.version      = { increment: 1 };
    }

    if (input.enabled !== undefined)        updateData.enabled        = input.enabled;
    if (input.organizationId !== undefined) updateData.organizationId = input.organizationId;

    const updated = await prisma.logDecoder.update({
      where: { id: params.id },
      data:  updateData,
    });

    // Reload decoders
    await loadDecoders();

    return NextResponse.json({ decoder: updated });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    if (err instanceof z.ZodError) return NextResponse.json({ error: "validation", detail: err.errors }, { status: 422 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── DELETE /api/log-analysis/decoders/[id] ──────────────────────────────────
export async function DELETE(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);

    const existing = await prisma.logDecoder.findUnique({ where: { id: params.id } });
    if (!existing) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Deleting a built-in is unrestricted — it's restored the next time
    // "Seed Built-ins" is run.
    if (!existing.isBuiltin) {
      if (!existing.organizationId || !actor.organizationIds.includes(existing.organizationId)) {
        return NextResponse.json({ error: "forbidden" }, { status: 403 });
      }
    }

    await prisma.logDecoder.delete({ where: { id: params.id } });
    await loadDecoders();

    return NextResponse.json({ success: true });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
