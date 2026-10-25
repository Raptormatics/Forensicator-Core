export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { actorOr401, guardOrgAccess, canAccessOrg } from "@/lib/auth/org-access";

type Params = { params: Promise<{ id: string }> };

// POST /api/cases/[id]/investigations  — link an investigation to the case.
// An investigation belongs to at most one case, so this fails with 409 if
// it's already linked elsewhere — unlink it from that case first.
export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  const orgActor = await actorOr401(req);
  if (orgActor instanceof NextResponse) return orgActor;
  const orgDenied = await guardOrgAccess(orgActor, { caseId: params.id });
  if (orgDenied) return orgDenied;
  const { investigationId } = await req.json();
  if (!investigationId)
    return NextResponse.json({ error: "investigationId required" }, { status: 400 });

  const kase = await prisma.case.findUnique({ where: { id: params.id }, select: { status: true, organizationId: true } });
  if (!kase) return NextResponse.json({ error: "Case not found" }, { status: 404 });
  if (kase.status === "closed") {
    return NextResponse.json({ error: "This case is closed — reopen it before linking investigations." }, { status: 403 });
  }

  const inv = await prisma.investigation.findUnique({ where: { id: investigationId }, select: { id: true, caseId: true, archivedAt: true, organizationId: true } });
  // An investigation can only join a case in its own organization (404, not 403:
  // another organization's investigation is treated as not existing).
  if (!inv || !canAccessOrg(orgActor, inv.organizationId) || inv.organizationId !== kase.organizationId) {
    return NextResponse.json({ error: "Investigation not found" }, { status: 404 });
  }
  if (inv.archivedAt) {
    return NextResponse.json(
      { error: "This investigation is archived — restore it from the Archive page before linking it to a case.", code: "archived" },
      { status: 403 },
    );
  }
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
  const orgActor = await actorOr401(req);
  if (orgActor instanceof NextResponse) return orgActor;
  const orgDenied = await guardOrgAccess(orgActor, { caseId: params.id });
  if (orgDenied) return orgDenied;
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
