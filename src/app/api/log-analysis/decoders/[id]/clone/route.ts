export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma }              from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { compileDecoder }      from "@/lib/log-analysis/decoder-engine/engine";
import yaml                    from "js-yaml";

// ── POST /api/log-analysis/decoders/[id]/clone ──────────────────────────────
export async function POST(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const actor = await getActorOrThrow(req);

    const source = await prisma.logDecoder.findUnique({ where: { id: params.id } });
    if (!source) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Parse the YAML to get the existing name, then rename
    let parsedYaml: Record<string, unknown>;
    try {
      parsedYaml = yaml.load(source.yamlContent) as Record<string, unknown>;
    } catch {
      return NextResponse.json({ error: "invalid_yaml" }, { status: 400 });
    }

    // Generate a unique name for the clone
    const originalName = String(parsedYaml.name ?? source.name);
    const clonedName   = originalName.replace(/\/(\d+)$/, (_, v) => `/${parseInt(v, 10) + 1}`) + "-clone";
    parsedYaml.name    = clonedName;
    if (parsedYaml.metadata && typeof parsedYaml.metadata === "object") {
      (parsedYaml.metadata as Record<string, unknown>).title =
        `[Clone] ${(parsedYaml.metadata as Record<string, unknown>).title ?? source.title ?? clonedName}`;
    }

    const clonedYaml = yaml.dump(parsedYaml);

    let def;
    try {
      def = compileDecoder(clonedYaml, false);
    } catch (err) {
      return NextResponse.json({ error: "invalid_yaml", detail: String(err) }, { status: 400 });
    }

    const cloned = await prisma.logDecoder.create({
      data: {
        name:           def.name,
        title:          def.title ?? null,
        description:    def.description ?? null,
        yamlContent:    clonedYaml,
        enabled:        false, // clones start disabled
        isBuiltin:      false,
        version:        1,
        createdById:    actor.id,
        organizationId: actor.organizationIds[0] ?? null,
      },
    });

    return NextResponse.json({ decoder: cloned }, { status: 201 });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    const msg = String(err);
    if (msg.includes("Unique constraint")) return NextResponse.json({ error: "decoder_name_exists" }, { status: 409 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
