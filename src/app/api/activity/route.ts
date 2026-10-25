/**
 * GET /api/activity?investigationId=&limit= — activity feed for an investigation, or across
 * the caller's organizations (plus the caller's own actions).
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { orgWhere } from "@/lib/auth/api-guard";
import { actorOr401, guardOrgAccess } from "@/lib/auth/org-access";

export async function GET(request: NextRequest) {
  const actor = await actorOr401(request);
  if (actor instanceof NextResponse) return actor;
  const sp = request.nextUrl.searchParams;
  const investigationId = sp.get("investigationId");
  const limit = Math.min(Number(sp.get("limit") ?? 50), 200);

  if (investigationId) {
    const denied = await guardOrgAccess(actor, { investigationId });
    if (denied) return denied;
  }
  const scope = orgWhere(actor);
  const logs = await prisma.activityLog.findMany({
    where: investigationId
      ? { investigationId }
      : Object.keys(scope).length ? { OR: [{ userId: actor.id }, { investigation: scope }] } : {},
    orderBy: { createdAt: "desc" },
    take: limit,
    include: {
      user: { select: { id: true, name: true, email: true } },
    },
  });

  return NextResponse.json({ logs });
}
