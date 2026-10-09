export const runtime = "nodejs";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  const scope = orgWhere(actor);

  const { searchParams } = new URL(req.url);
  const page    = Math.max(1, Number(searchParams.get("page") ?? 1));
  const limit   = Math.min(100, Number(searchParams.get("limit") ?? 50));
  const actorQ  = searchParams.get("actorEmail") ?? undefined;
  const action  = searchParams.get("action") ?? undefined;
  const resType = searchParams.get("resourceType") ?? undefined;
  const severity= searchParams.get("severity") ?? undefined;
  const q       = searchParams.get("q") ?? undefined;

  const where = {
    ...scope,
    ...(actorQ   ? { actorEmail: { contains: actorQ, mode: "insensitive" as const } } : {}),
    ...(action   ? { action: { contains: action, mode: "insensitive" as const } } : {}),
    ...(resType  ? { resourceType: resType } : {}),
    ...(severity ? { severity } : {}),
    ...(q        ? {
      OR: [
        { action: { contains: q, mode: "insensitive" as const } },
        { actorEmail: { contains: q, mode: "insensitive" as const } },
        { resourceType: { contains: q, mode: "insensitive" as const } },
      ],
    } : {}),
  };

  const [total, logs] = await Promise.all([
    prisma.auditLog.count({ where }),
    prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * limit,
      take: limit,
      include: { actor: { select: { id: true, email: true } } },
    }),
  ]);

  return NextResponse.json({ logs, total, page, limit, pages: Math.ceil(total / limit) });
}
