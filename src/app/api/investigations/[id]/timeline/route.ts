import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";

const querySchema = z.object({
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  category: z.string().optional(),
  severity: z.string().optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  q: z.string().max(200).optional(),
  realOnly: z.coerce.boolean().optional().default(false),
});

// The collector fallback for findings with no real evidence timestamp —
// see extractTimelineEvents (src/lib/upload/evidence-extractor.ts) for the
// full story. realOnly=true excludes just this; older investigations'
// undifferentiated "finding_timeline" rows (uploaded before this distinction
// existed) are treated as unknown provenance, not definitely noise, so they
// stay visible even with the filter on.
const COLLECTION_TIME_SOURCE_TYPE = "finding_collected";

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

  const { cursor, limit, category, severity, from, to, q, realOnly } = parsed.data;

  const where = {
    investigationId: params.id,
    ...(category ? { category } : {}),
    ...(severity ? { severity } : {}),
    ...(realOnly ? { sourceType: { not: COLLECTION_TIME_SOURCE_TYPE } } : {}),
    ...(from || to
      ? {
          timestamp: {
            ...(from ? { gte: new Date(from) } : {}),
            ...(to ? { lte: new Date(to) } : {}),
          },
        }
      : {}),
    ...(q
      ? {
          OR: [
            { title: { contains: q, mode: "insensitive" as const } },
            { description: { contains: q, mode: "insensitive" as const } },
          ],
        }
      : {}),
  };

  const [events, categoryFacets, collectionTimeCount, totalCount] = await Promise.all([
    prisma.timelineEvent.findMany({
      where,
      orderBy: { timestamp: "desc" },
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
      select: {
        id: true,
        timestamp: true,
        title: true,
        description: true,
        category: true,
        severity: true,
        sourceType: true,
        evidenceId: true,
        findingId: true,
        metadata: true,
      },
    }),
    prisma.timelineEvent.groupBy({
      by: ["category"],
      where: { investigationId: params.id },
      _count: true,
    }),
    prisma.timelineEvent.count({
      where: { investigationId: params.id, sourceType: COLLECTION_TIME_SOURCE_TYPE },
    }),
    prisma.timelineEvent.count({ where: { investigationId: params.id } }),
  ]);

  const hasMore = events.length > limit;
  const page = hasMore ? events.slice(0, limit) : events;
  const nextCursor = hasMore ? page[page.length - 1]?.id : null;

  return NextResponse.json({
    events: page,
    nextCursor,
    hasMore,
    categories: categoryFacets.map((c) => c.category).sort(),
    total: totalCount,
    collectionTimeCount,
  });
}
