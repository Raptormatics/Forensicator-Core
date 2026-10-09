import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

const querySchema = z.object({
  type: z.string().optional(),
  q: z.string().max(500).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  sort: z.enum(["timestamp", "type", "processName", "ip", "url", "createdAt"]).default("createdAt"),
  dir: z.enum(["asc", "desc"]).default("desc"),
});

export async function GET(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(request); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const investigation = await prisma.investigation.findFirst({
    where: { id: params.id, ...orgWhere(actor) },
    select: { id: true },
  });
  if (!investigation) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const parsed = querySchema.safeParse(
    Object.fromEntries(request.nextUrl.searchParams)
  );

  if (!parsed.success) {
    return NextResponse.json(
      { error: "invalid_params", issues: parsed.error.flatten() },
      { status: 400 }
    );
  }

  const { type, q, page, limit, sort, dir } = parsed.data;

  const where = {
    investigationId: params.id,
    ...(type ? { type: { equals: type, mode: "insensitive" as const } } : {}),
    ...(q
      ? {
          OR: [
            { searchableText: { contains: q, mode: "insensitive" as const } },
            { url: { contains: q, mode: "insensitive" as const } },
            { ip: { contains: q, mode: "insensitive" as const } },
            { processName: { contains: q, mode: "insensitive" as const } },
            { commandLine: { contains: q, mode: "insensitive" as const } },
            { username: { contains: q, mode: "insensitive" as const } },
            { hostname: { contains: q, mode: "insensitive" as const } },
            { domain: { contains: q, mode: "insensitive" as const } },
            { hash: { contains: q, mode: "insensitive" as const } },
          ],
        }
      : {}),
  };

  const [total, rows, types] = await Promise.all([
    prisma.evidence.count({ where }),
    prisma.evidence.findMany({
      where,
      orderBy: { [sort]: dir },
      skip: (page - 1) * limit,
      take: limit,
      select: {
        id: true,
        type: true,
        source: true,
        timestamp: true,
        hostname: true,
        username: true,
        url: true,
        ip: true,
        domain: true,
        hash: true,
        processName: true,
        commandLine: true,
        findingId: true,
        raw: true,
      },
    }),
    // Distinct types for the tab/filter bar.
    prisma.evidence.findMany({
      where: { investigationId: params.id },
      select: { type: true },
      distinct: ["type"],
      orderBy: { type: "asc" },
    }),
  ]);

  return NextResponse.json({
    rows,
    total,
    page,
    limit,
    pages: Math.ceil(total / limit),
    types: types.map((t) => t.type),
  });
}
