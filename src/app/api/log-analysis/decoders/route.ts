export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma }              from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { z }                   from "zod";
import { compileDecoder, loadDecoders } from "@/lib/log-analysis/decoder-engine/engine";

const CreateSchema = z.object({
  yamlContent:    z.string().min(10),
  organizationId: z.string().uuid().optional().nullable(),
  isBuiltin:      z.boolean().optional(),
});

// ── GET /api/log-analysis/decoders ──────────────────────────────────────────
export async function GET(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    const { searchParams } = new URL(req.url);
    const builtinOnly = searchParams.get("builtin") === "true";
    const customOnly  = searchParams.get("custom")  === "true";

    const where: Record<string, unknown> = {};
    if (builtinOnly) where.isBuiltin = true;
    if (customOnly)  where.isBuiltin = false;

    // Everyone sees their org's custom decoders + all built-ins (Core has
    // exactly one org, so this isn't really a restriction).
    where.OR = [
      { isBuiltin: true },
      { organizationId: { in: actor.organizationIds } },
    ];

    const decoders = await prisma.logDecoder.findMany({
      where,
      orderBy: [{ isBuiltin: "asc" }, { name: "asc" }],
      select: {
        id: true, name: true, title: true, description: true,
        enabled: true, isBuiltin: true, version: true,
        createdAt: true, updatedAt: true,
        createdBy: { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
      },
    });

    return NextResponse.json({ decoders });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── POST /api/log-analysis/decoders ─────────────────────────────────────────
// Creates a custom decoder from scratch (hand-written YAML or via the
// visual builder UI). Cloning (decoders/[id]/clone/route.ts) is a separate,
// unaffected endpoint.
export async function POST(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    const body  = await req.json();
    const input = CreateSchema.parse(body);

    // Validate + compile YAML before persisting
    let def;
    try {
      def = compileDecoder(input.yamlContent, false);
    } catch (err) {
      return NextResponse.json({ error: "invalid_yaml", detail: String(err) }, { status: 400 });
    }

    const decoder = await prisma.logDecoder.create({
      data: {
        name:           def.name,
        title:          def.title ?? null,
        description:    def.description ?? null,
        yamlContent:    input.yamlContent,
        enabled:        true,
        isBuiltin:      input.isBuiltin ?? false,
        version:        1,
        createdById:    actor.id,
        organizationId: input.organizationId ?? actor.organizationIds[0] ?? null,
      },
    });

    // Reload decoders so the new one is available immediately
    await loadDecoders();

    return NextResponse.json({ decoder }, { status: 201 });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    if (err instanceof z.ZodError) return NextResponse.json({ error: "validation", detail: err.errors }, { status: 422 });
    const msg = String(err);
    if (msg.includes("Unique constraint")) return NextResponse.json({ error: "decoder_name_exists" }, { status: 409 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
