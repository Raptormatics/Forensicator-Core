export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

type Params = { params: Promise<{ id: string }> };

// POST /api/cases/[id]/playbooks/apply — stamp a playbook's tasks into this
// case's real CaseTask rows, and set Case.incidentType to match.
export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const kase = await prisma.case.findFirst({ where: { id: params.id, ...orgWhere(actor) } });
  if (!kase) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const body = await req.json().catch(() => ({}));
  const incidentType = typeof body.incidentType === "string" ? body.incidentType : "";
  if (!incidentType) {
    return NextResponse.json({ error: "incidentType is required" }, { status: 400 });
  }

  const playbook = await prisma.playbook.findUnique({
    where: { incidentType },
    include: { tasks: { orderBy: { order: "asc" } } },
  });
  if (!playbook) {
    return NextResponse.json({ error: "playbook_not_found" }, { status: 404 });
  }

  const result = await prisma.$transaction(async (tx) => {
    const created = await tx.caseTask.createMany({
      data: playbook.tasks.map((t) => ({
        caseId: params.id,
        title: t.title,
        notes: t.notes,
        priority: t.priority,
        createdById: actor.id,
      })),
    });
    await tx.case.update({ where: { id: params.id }, data: { incidentType } });
    return created;
  });

  return NextResponse.json({ applied: result.count, playbook: { id: playbook.id, name: playbook.name } });
}
