export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

type Params = { params: Promise<{ id: string }> };

// GET /api/investigations/[id]/attack-path
export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const investigation = await prisma.investigation.findFirst({
    where: { id: params.id, ...orgWhere(actor) },
    select: { id: true },
  });
  if (!investigation) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const path = await prisma.attackPath.findFirst({
    where: { investigationId: params.id },
    orderBy: { generatedAt: "desc" },
  });
  if (!path) return NextResponse.json({ error: "No attack path generated yet" }, { status: 404 });
  return NextResponse.json({ attackPath: path });
}
