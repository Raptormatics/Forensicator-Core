export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

type Params = { params: Promise<{ id: string; taskId: string }> };

async function loadOwnedTask(caseId: string, taskId: string, actor: Awaited<ReturnType<typeof getActorOrThrow>>) {
  const kase = await prisma.case.findFirst({ where: { id: caseId, ...orgWhere(actor) } });
  if (!kase) return null;
  const task = await prisma.caseTask.findFirst({ where: { id: taskId, caseId } });
  return task;
}

// PATCH /api/cases/[id]/tasks/[taskId] — partial update
export async function PATCH(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const existing = await loadOwnedTask(params.id, params.taskId, actor);
  if (!existing) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const body = await req.json().catch(() => ({}));
  const { title, notes, status, priority, dueAt, ownerId, relatedFindingIds } = body;

  if (status !== undefined && !["todo", "in_progress", "done"].includes(status)) {
    return NextResponse.json({ error: "invalid_status" }, { status: 400 });
  }
  if (priority !== undefined && !["critical", "high", "medium", "low"].includes(priority)) {
    return NextResponse.json({ error: "invalid_priority" }, { status: 400 });
  }

  const task = await prisma.caseTask.update({
    where: { id: params.taskId },
    data: {
      ...(title             !== undefined ? { title: String(title).trim() } : {}),
      ...(notes             !== undefined ? { notes } : {}),
      ...(status             !== undefined ? { status } : {}),
      ...(priority           !== undefined ? { priority } : {}),
      ...(dueAt              !== undefined ? { dueAt: dueAt ? new Date(dueAt) : null } : {}),
      ...(ownerId            !== undefined ? { ownerId } : {}),
      ...(relatedFindingIds  !== undefined ? { relatedFindingIds } : {}),
    },
    include: {
      owner:     { select: { id: true, email: true, name: true } },
      createdBy: { select: { id: true, email: true, name: true } },
    },
  });

  return NextResponse.json({ task });
}

// DELETE /api/cases/[id]/tasks/[taskId]
export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const existing = await loadOwnedTask(params.id, params.taskId, actor);
  if (!existing) return NextResponse.json({ error: "not_found" }, { status: 404 });

  await prisma.caseTask.delete({ where: { id: params.taskId } });
  return NextResponse.json({ ok: true });
}
