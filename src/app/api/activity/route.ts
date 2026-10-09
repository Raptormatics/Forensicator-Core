/**
 * GET /api/activity?investigationId=&limit= — activity feed for an investigation or global.
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";

export async function GET(request: NextRequest) {
  const sp = request.nextUrl.searchParams;
  const investigationId = sp.get("investigationId");
  const limit = Math.min(Number(sp.get("limit") ?? 50), 200);

  const logs = await prisma.activityLog.findMany({
    where: investigationId ? { investigationId } : {},
    orderBy: { createdAt: "desc" },
    take: limit,
    include: {
      user: { select: { id: true, name: true, email: true } },
    },
  });

  return NextResponse.json({ logs });
}
