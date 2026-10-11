export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";

// POST /api/correlations/whitelist — mark a correlation entity as known-good.
// Suppression is a display concern only; matching Correlation rows are untouched.
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const body = await req.json().catch(() => ({}));
  const correlationType = typeof body.correlationType === "string" ? body.correlationType : undefined;
  const value = typeof body.value === "string" ? body.value : undefined;
  const note = typeof body.note === "string" ? body.note.trim() || null : null;
  if (!correlationType || !value) {
    return NextResponse.json({ error: "correlationType and value are required" }, { status: 400 });
  }

  const organizationId = actor.organizationIds[0] ?? null;
  const entry = await prisma.correlationWhitelist.upsert({
    where: { correlationType_value_organizationId: { correlationType, value, organizationId } },
    update: { note },
    create: { correlationType, value, note, createdById: actor.id, organizationId },
  });
  return NextResponse.json({ entry }, { status: 201 });
}

// DELETE /api/correlations/whitelist — un-whitelist (body: { correlationType, value })
export async function DELETE(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const body = await req.json().catch(() => ({}));
  const correlationType = typeof body.correlationType === "string" ? body.correlationType : undefined;
  const value = typeof body.value === "string" ? body.value : undefined;
  if (!correlationType || !value) {
    return NextResponse.json({ error: "correlationType and value are required" }, { status: 400 });
  }

  const organizationId = actor.organizationIds[0] ?? null;
  await prisma.correlationWhitelist.deleteMany({ where: { correlationType, value, organizationId } });
  return NextResponse.json({ ok: true });
}
