export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { guardCaseOpen } from "@/lib/cases/case-lock";
import { guardOrgAccess } from "@/lib/auth/org-access";

/** GET /api/known-hashes?caseId=X — how many known-good hashes are linked to this case. */
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const caseId = req.nextUrl.searchParams.get("caseId");
  if (!caseId) {
    return NextResponse.json({ error: "missing_case", message: "caseId is required." }, { status: 400 });
  }
  const denied = await guardOrgAccess(actor, { caseId });
  if (denied) return denied;

  const count = await prisma.caseKnownHash.count({ where: { caseId } });
  return NextResponse.json({ count });
}

/** DELETE /api/known-hashes?caseId=X — clear every known-hash link from this case (does not delete the global KnownHash rows, just this case's visibility of them). */
export async function DELETE(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const caseId = req.nextUrl.searchParams.get("caseId");
  if (!caseId) {
    return NextResponse.json({ error: "missing_case", message: "caseId is required." }, { status: 400 });
  }
  const denied = await guardOrgAccess(actor, { caseId });
  if (denied) return denied;

  const locked = await guardCaseOpen({ caseId }, "unlinking its known hashes");
  if (locked) return locked;

  const result = await prisma.caseKnownHash.deleteMany({ where: { caseId } });
  return NextResponse.json({ removed: result.count });
}
