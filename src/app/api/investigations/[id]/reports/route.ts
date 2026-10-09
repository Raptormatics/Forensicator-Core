/**
 * GET /api/investigations/[id]/reports — list reports for an investigation.
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

export async function GET(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const investigation = await prisma.investigation.findFirst({
    where: { id: params.id, ...orgWhere(actor) },
    select: { id: true },
  });
  if (!investigation) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const reports = await prisma.report.findMany({
    where: { investigationId: params.id },
    orderBy: { createdAt: "desc" },
    select: {
      id: true, type: true, format: true, status: true,
      fileSize: true, errorMessage: true, createdAt: true,
      generatedBy: { select: { name: true, email: true } },
    },
  });
  return NextResponse.json({ reports });
}
