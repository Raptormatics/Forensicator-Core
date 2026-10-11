export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Core ships no POST here — creating a rule is custom-rule *authoring*,
 * an Enterprise-only capability (see src/prisma/schema/ram-analysis.prisma).
 * This isn't a role/UI-level restriction on top of working create logic;
 * the create logic itself doesn't exist in this file. Core is open source,
 * so a check gating otherwise-functional code would be trivially
 * bypassable by anyone reading or forking it — the only real boundary is
 * that this code isn't here. The Enterprise overlay replaces this file
 * with a version that adds POST back (see that file's own header comment).
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";

// ── GET /api/ram-analysis/rules ─────────────────────────────────────────────
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

    const rules = await prisma.ramAnalysisRule.findMany({
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
