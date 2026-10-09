export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

type Params = { params: Promise<{ id: string }> };

const STATUS_RANK: Record<string, number> = { todo: 0, in_progress: 1, done: 2 };
const PRIORITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

// GET /api/cases/[id]/tasks — list a case's task checklist
export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const kase = await prisma.case.findFirst({ where: { id: params.id, ...orgWhere(actor) } });
  if (!kase) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const tasks = await prisma.caseTask.findMany({
    where: { caseId: params.id },
    include: {
      owner:     { select: { id: true, email: true, name: true } },
      createdBy: { select: { id: true, email: true, name: true } },
    },
  });

  tasks.sort((a, b) =>
    STATUS_RANK[a.status] - STATUS_RANK[b.status] ||
    PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] ||
    (a.dueAt?.getTime() ?? Infinity) - (b.dueAt?.getTime() ?? Infinity)
  );

  return NextResponse.json({ tasks });
}

// POST /api/cases/[id]/tasks — create a task
export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const kase = await prisma.case.findFirst({ where: { id: params.id, ...orgWhere(actor) } });
  if (!kase) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const body = await req.json().catch(() => ({}));
  const title = typeof body.title === "string" ? body.title.trim() : "";
  if (!title) return NextResponse.json({ error: "title is required" }, { status: 400 });

  const task = await prisma.caseTask.create({
    data: {
      caseId: params.id,
      title,
      notes: typeof body.notes === "string" ? body.notes : null,
      status: ["todo", "in_progress", "done"].includes(body.status) ? body.status : "todo",
      priority: ["critical", "high", "medium", "low"].includes(body.priority) ? body.priority : "medium",
      dueAt: body.dueAt ? new Date(body.dueAt) : null,
      ownerId: body.ownerId ?? null,
      createdById: actor.id,
      relatedFindingIds: Array.isArray(body.relatedFindingIds) ? body.relatedFindingIds : [],
    },
    include: {
      owner:     { select: { id: true, email: true, name: true } },
      createdBy: { select: { id: true, email: true, name: true } },
    },
  });

  return NextResponse.json({ task }, { status: 201 });
}
