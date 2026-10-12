export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Core ships no POST here — creating a brand-new decoder from scratch
 * (hand-written YAML or, in the overlay, the visual builder) is custom
 * decoder *authoring*, an Enterprise-only capability, and that code
 * doesn't exist in this file at all (not a check gating otherwise-working
 * logic — Core is open source, so that would be trivially bypassable).
 * Cloning a decoder (decoders/[id]/clone/route.ts) stays free in Core —
 * that's forking an existing decoder to customize it, a different thing
 * from authoring one from nothing, and has its own, unaffected endpoint.
 * The Enterprise overlay replaces this file with a version that adds
 * POST back (see that file's own header comment).
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma }              from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";

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

    // Non-admin users see only their org's custom decoders + all built-ins
    if (actor.role !== "platform_admin") {
      where.OR = [
        { isBuiltin: true },
        { organizationId: { in: actor.organizationIds } },
      ];
    }

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
