export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActor } from "@/lib/auth/actor";

type Params = { params: Promise<{ id: string }> };

// GET /api/cases/[id]
export async function GET(_req: NextRequest, props: Params) {
  const params = await props.params;
  const c = await prisma.case.findUnique({
    where: { id: params.id },
    include: {
      createdBy:  { select: { id: true, email: true, name: true } },
      assignee:   { select: { id: true, email: true, name: true } },
      notes:      { orderBy: { createdAt: "desc" }, include: { author: { select: { email: true, name: true } } } },
      investigations: {
        select: { id: true, title: true, hostname: true, status: true, findingCount: true },
      },
    },
  });
  if (!c) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ case: c });
}

// PATCH /api/cases/[id]
export async function PATCH(req: NextRequest, props: Params) {
  const params = await props.params;
  const body = await req.json();
  const { title, description, status, severity, tags, assigneeId, incidentType } = body;

  if (assigneeId !== undefined) {
    const kase = await prisma.case.findUnique({ where: { id: params.id }, select: { status: true } });
    if (!kase) return NextResponse.json({ error: "Case not found" }, { status: 404 });
    if (kase.status === "closed") {
      return NextResponse.json({ error: "This case is closed — reopen it before changing the assignee." }, { status: 403 });
    }
  }

  const c = await prisma.case.update({
    where: { id: params.id },
    data: {
      ...(title       !== undefined ? { title }       : {}),
      ...(description !== undefined ? { description } : {}),
      ...(status      !== undefined ? { status }      : {}),
      ...(severity    !== undefined ? { severity }    : {}),
      ...(tags        !== undefined ? { tags }        : {}),
      ...(assigneeId  !== undefined ? { assigneeId }  : {}),
      ...(incidentType !== undefined ? { incidentType: incidentType || null } : {}),
    },
  });
  return NextResponse.json({ case: c });
}

// DELETE /api/cases/[id]
export async function DELETE(_req: NextRequest, props: Params) {
  const params = await props.params;
  await prisma.case.delete({ where: { id: params.id } });
  return NextResponse.json({ ok: true });
}
