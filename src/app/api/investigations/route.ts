export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma }            from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";

// ── GET /api/investigations ─────────────────────────────────────────────────
// Lightweight list used by pickers (e.g. link-to-case). Returns id, title,
// hostname, status and createdAt only — no findings payload.
export async function GET(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);

    const where = actor.role === "platform_admin"
      ? {}
      : { organizationId: { in: actor.organizationIds } };

    const { searchParams } = new URL(req.url);
    const q = searchParams.get("q")?.trim();
    if (q) {
      (where as Record<string, unknown>).OR = [
        { title:    { contains: q, mode: "insensitive" } },
        { hostname: { contains: q, mode: "insensitive" } },
      ];
    }

    const investigations = await prisma.investigation.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: 100,
      select: {
        id:           true,
        title:        true,
        hostname:     true,
        status:       true,
        findingCount: true,
        createdAt:    true,
        caseId:       true,
      },
    });

    return NextResponse.json({ investigations });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
