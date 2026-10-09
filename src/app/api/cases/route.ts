export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

// GET /api/cases — list cases scoped to actor's org
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  const { searchParams } = new URL(req.url);
  const status   = searchParams.get("status") ?? undefined;
  const severity = searchParams.get("severity") ?? undefined;
  const q        = searchParams.get("q") ?? undefined;

  const cases = await prisma.case.findMany({
    where: {
      ...orgWhere(actor),
      ...(status   ? { status }   : {}),
      ...(severity ? { severity } : {}),
      ...(q        ? { OR: [{ title: { contains: q, mode: "insensitive" } }, { description: { contains: q, mode: "insensitive" } }] } : {}),
    },
    include: {
      createdBy:  { select: { id: true, email: true, name: true } },
      assignee:   { select: { id: true, email: true, name: true } },
      _count:     { select: { investigations: true, notes: true } },
    },
    orderBy: { updatedAt: "desc" },
  });

  return NextResponse.json({ cases });
}

// POST /api/cases — create a case, auto-assign to actor's primary org
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  const body  = await req.json();
  const { title, description, status, severity, tags, organizationId } = body;

  if (!title) return NextResponse.json({ error: "title is required" }, { status: 400 });

  // Resolve org: explicit param > actor's primary org > null
  const resolvedOrgId: string | null =
    organizationId ?? actor.organizationIds[0] ?? null;

  const c = await prisma.case.create({
    data: {
      title,
      description: description ?? null,
      status:      status      ?? "open",
      severity:    severity    ?? "medium",
      tags:        tags        ?? [],
      createdById: actor.id,
      organizationId: resolvedOrgId,
    },
  });

  return NextResponse.json({ case: c }, { status: 201 });
}
