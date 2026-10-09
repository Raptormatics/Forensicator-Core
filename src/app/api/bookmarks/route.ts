/**
 * GET  /api/bookmarks          — list current user's bookmarks
 * POST /api/bookmarks          — toggle (create or delete) a bookmark
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";

export const runtime = "nodejs";

const toggleSchema = z.object({
  entityType:     z.enum(["investigation", "finding", "evidence", "ioc", "timeline"]),
  entityId:       z.string().min(1),
  label:          z.string().max(200).optional(),
  investigationId: z.string().uuid().optional(),
  findingId:       z.string().uuid().optional(),
  timelineEventId: z.string().uuid().optional(),
});

export async function GET(request: NextRequest) {
  const actor = await getUploadActor(request);
  const bookmarks = await prisma.bookmark.findMany({
    where: { userId: actor.id },
    orderBy: { createdAt: "desc" },
  });
  return NextResponse.json({ bookmarks });
}

export async function POST(request: NextRequest) {
  try {
    const body = toggleSchema.parse(await request.json());
    const actor = await getUploadActor(request);

    const existing = await prisma.bookmark.findUnique({
      where: { userId_entityType_entityId: { userId: actor.id, entityType: body.entityType, entityId: body.entityId } },
    });

    if (existing) {
      await prisma.bookmark.delete({ where: { id: existing.id } });
      return NextResponse.json({ bookmarked: false });
    }

    const bm = await prisma.bookmark.create({
      data: {
        userId: actor.id,
        entityType: body.entityType,
        entityId: body.entityId,
        label: body.label ?? null,
        investigationId: body.investigationId ?? null,
        findingId: body.findingId ?? null,
        timelineEventId: body.timelineEventId ?? null,
      },
    });
    return NextResponse.json({ bookmarked: true, bookmark: bm }, { status: 201 });
  } catch (err) {
    if (err instanceof z.ZodError) return NextResponse.json({ error: "invalid_params", issues: err.flatten() }, { status: 400 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
