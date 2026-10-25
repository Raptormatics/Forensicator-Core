/**
 * GET  /api/notes?investigationId=&findingId=&evidenceId= — list notes
 * POST /api/notes — create note
 */
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";
import { actorOr401, guardOrgAccess, type OrgRef } from "@/lib/auth/org-access";
import { guardCaseOpen } from "@/lib/cases/case-lock";

export const runtime = "nodejs";

const createSchema = z.object({
  content:        z.string().min(1).max(50000),
  investigationId: z.string().uuid().optional(),
  findingId:       z.string().uuid().optional(),
  evidenceId:      z.string().uuid().optional(),
});

/** The record a note is attached to, as an org-access ref (the most specific one given). */
function noteTarget(ids: { investigationId?: string | null; findingId?: string | null; evidenceId?: string | null }): OrgRef | null {
  if (ids.findingId) return { findingId: ids.findingId };
  if (ids.evidenceId) return { evidenceId: ids.evidenceId };
  if (ids.investigationId) return { investigationId: ids.investigationId };
  return null;
}

export async function GET(request: NextRequest) {
  const actor = await actorOr401(request);
  if (actor instanceof NextResponse) return actor;
  const sp = request.nextUrl.searchParams;
  const where: Record<string, unknown> = {};
  if (sp.get("investigationId")) where.investigationId = sp.get("investigationId");
  if (sp.get("findingId"))       where.findingId       = sp.get("findingId");
  if (sp.get("evidenceId"))      where.evidenceId      = sp.get("evidenceId");
  // Notes are only listed for a record the caller can access.
  const target = noteTarget({ investigationId: sp.get("investigationId"), findingId: sp.get("findingId"), evidenceId: sp.get("evidenceId") });
  if (!target) return NextResponse.json({ error: "investigationId, findingId or evidenceId is required" }, { status: 400 });
  for (const ref of [sp.get("investigationId") && { investigationId: sp.get("investigationId")! }, sp.get("findingId") && { findingId: sp.get("findingId")! }, sp.get("evidenceId") && { evidenceId: sp.get("evidenceId")! }]) {
    if (!ref) continue;
    const denied = await guardOrgAccess(actor, ref as OrgRef);
    if (denied) return denied;
  }

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
    for (const ref of [body.investigationId && { investigationId: body.investigationId }, body.findingId && { findingId: body.findingId }, body.evidenceId && { evidenceId: body.evidenceId }]) {
      if (!ref) continue;
      const denied = await guardOrgAccess(actor, ref as OrgRef);
      if (denied) return denied;
    }
    const locked = body.investigationId ? await guardCaseOpen({ investigationId: body.investigationId }, "adding notes")
      : body.findingId ? await guardCaseOpen({ findingId: body.findingId }, "adding notes")
      : body.evidenceId ? await guardCaseOpen({ evidenceId: body.evidenceId }, "adding notes")
      : null;
    if (locked) return locked;

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
