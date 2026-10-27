export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, isInstanceAdminActor } from "@/lib/auth/api-guard";
import { instanceAdminRequired } from "@/lib/auth/org-access";

type Params = { params: Promise<{ id: string }> };

/** GET /api/sigma/rules/[id] — one rule with its YAML. */
export async function GET(req: NextRequest, props: Params) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }
  const { id } = await props.params;
  const rule = await prisma.sigmaRule.findUnique({
    where: { id },
    select: { id: true, sigmaId: true, title: true, description: true, status: true, level: true, author: true, tags: true,
      references: true, falsePositives: true, product: true, category: true, service: true, path: true, yaml: true,
      supported: true, covered: true, unsupportedReason: true, enabled: true, source: true, hitCount: true, updatedAt: true },
  });
  if (!rule) return NextResponse.json({ error: "not_found" }, { status: 404 });
  return NextResponse.json({ rule });
}

/** PATCH /api/sigma/rules/[id] — { enabled } */
export async function PATCH(req: NextRequest, props: Params) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }
  if (!isInstanceAdminActor(actor)) return instanceAdminRequired();
  const { id } = await props.params;
  const body = (await req.json().catch(() => ({}))) as { enabled?: unknown };
  if (typeof body.enabled !== "boolean") return NextResponse.json({ error: "invalid_body", message: "enabled must be true or false" }, { status: 400 });
  const rule = await prisma.sigmaRule.update({ where: { id }, data: { enabled: body.enabled }, select: { id: true, enabled: true } }).catch(() => null);
  if (!rule) return NextResponse.json({ error: "not_found" }, { status: 404 });
  return NextResponse.json({ rule });
}
