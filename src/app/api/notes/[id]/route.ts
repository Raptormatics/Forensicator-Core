/**
 * PATCH /api/notes/[id] — edit note content
 * DELETE /api/notes/[id]
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getUploadActor } from "@/lib/upload/actor";
import { guardCaseOpen, guardDeletion } from "@/lib/cases/case-lock";
import { actorOr401, guardOrgAccess } from "@/lib/auth/org-access";

export const runtime = "nodejs";

export async function PATCH(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  const orgActor = await actorOr401(request);
  if (orgActor instanceof NextResponse) return orgActor;
  const orgDenied = await guardOrgAccess(orgActor, { noteId: params.id });
  if (orgDenied) return orgDenied;
  try {
    const { content } = z.object({ content: z.string().min(1).max(50000) }).parse(await request.json());
    const actor = await getUploadActor(request);

    const note = await prisma.note.findUnique({ where: { id: params.id } });
    if (!note) return NextResponse.json({ error: "not_found" }, { status: 404 });
    if (note.authorId !== actor.id) return NextResponse.json({ error: "forbidden" }, { status: 403 });
    const locked = await guardCaseOpen({ noteId: note.id }, "changing its notes");
    if (locked) return locked;

    const updated = await prisma.note.update({
      where: { id: params.id },
      data: { content },
      include: { author: { select: { id: true, name: true, email: true } } },
    });
    return NextResponse.json({ note: updated });
  } catch (err) {
    if (err instanceof z.ZodError) return NextResponse.json({ error: "invalid_params" }, { status: 400 });
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  const orgActor = await actorOr401(request);
  if (orgActor instanceof NextResponse) return orgActor;
  const orgDenied = await guardOrgAccess(orgActor, { noteId: params.id });
  if (orgDenied) return orgDenied;
  const actor = await getUploadActor(request);
  const note = await prisma.note.findUnique({ where: { id: params.id } });
  if (!note) return NextResponse.json({ error: "not_found" }, { status: 404 });
  if (note.authorId !== actor.id) return NextResponse.json({ error: "forbidden" }, { status: 403 });
  const locked = await guardDeletion({ noteId: note.id }, "deleting notes");
  if (locked) return locked;
  await prisma.note.delete({ where: { id: params.id } });
  return NextResponse.json({ deleted: true });
}
