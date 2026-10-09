export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";

type Params = { params: Promise<{ id: string }> };

// POST /api/cases/[id]/investigations  — link an investigation to the case.
// An investigation belongs to at most one case, so this fails with 409 if
// it's already linked elsewhere — unlink it from that case first.
export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  const { investigationId } = await req.json();
  if (!investigationId)
    return NextResponse.json({ error: "investigationId required" }, { status: 400 });

  const kase = await prisma.case.findUnique({ where: { id: params.id }, select: { status: true } });
  if (!kase) return NextResponse.json({ error: "Case not found" }, { status: 404 });
  if (kase.status === "closed") {
    return NextResponse.json({ error: "This case is closed — reopen it before linking investigations." }, { status: 403 });
  }

  const inv = await prisma.investigation.findUnique({ where: { id: investigationId }, select: { id: true, caseId: true } });
  if (!inv) return NextResponse.json({ error: "Investigation not found" }, { status: 404 });
  if (inv.caseId && inv.caseId !== params.id) {
    return NextResponse.json(
      { error: "An investigation can only belong to one case. Unlink it from its current case first." },
      { status: 409 }
    );
  }

  const updated = await prisma.investigation.update({
    where: { id: investigationId },
    data: { caseId: params.id },
  });
  return NextResponse.json({ investigation: updated }, { status: 201 });
}

// DELETE /api/cases/[id]/investigations  — unlink (body: { investigationId })
export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  const { investigationId } = await req.json();

  const kase = await prisma.case.findUnique({ where: { id: params.id }, select: { status: true } });
  if (!kase) return NextResponse.json({ error: "Case not found" }, { status: 404 });
  if (kase.status === "closed") {
    return NextResponse.json({ error: "This case is closed — reopen it before unlinking investigations." }, { status: 403 });
  }

  await prisma.investigation.updateMany({
    where: { id: investigationId, caseId: params.id },
    data: { caseId: null },
  });
  return NextResponse.json({ ok: true });
}
