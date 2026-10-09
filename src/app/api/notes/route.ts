/**
 * GET  /api/notes?investigationId=&findingId=&evidenceId= — list notes
 * POST /api/notes — create note
 */
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";

export const runtime = "nodejs";

const createSchema = z.object({
  content:        z.string().min(1).max(50000),
  investigationId: z.string().uuid().optional(),
  findingId:       z.string().uuid().optional(),
  evidenceId:      z.string().uuid().optional(),
});

export async function GET(request: NextRequest) {
  const sp = request.nextUrl.searchParams;
  const where: Record<string, unknown> = {};
  if (sp.get("investigationId")) where.investigationId = sp.get("investigationId");
  if (sp.get("findingId"))       where.findingId       = sp.get("findingId");
  if (sp.get("evidenceId"))      where.evidenceId      = sp.get("evidenceId");

  const notes = await prisma.note.findMany({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    where: where as any,
    orderBy: { createdAt: "desc" },
    include: { author: { select: { id: true, name: true, email: true } } },
  });

  return NextResponse.json({ notes });
}

export async function POST(request: NextRequest) {
  try {
    const body = createSchema.parse(await request.json());
    const actor = await getUploadActor(request);

    const note = await prisma.note.create({
      data: { ...body, authorId: actor.id },
      include: { author: { select: { id: true, name: true, email: true } } },
    });

    await prisma.activityLog.create({
      data: {
        userId: actor.id,
        action: "note_created",
        entityType: body.findingId ? "finding" : body.investigationId ? "investigation" : "evidence",
        entityId: (body.findingId ?? body.investigationId ?? body.evidenceId)!,
        investigationId: body.investigationId ?? null,
        metadata: { noteId: note.id } as never,
      },
    });

    return NextResponse.json({ note }, { status: 201 });
  } catch (err) {
    if (err instanceof z.ZodError) return NextResponse.json({ error: "invalid_params", issues: err.flatten() }, { status: 400 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
