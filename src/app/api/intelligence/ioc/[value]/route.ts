import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { actorOr401, investigationOrgWhere } from "@/lib/auth/org-access";

const querySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  page: z.coerce.number().int().min(1).default(1),
});

export async function GET(
  request: NextRequest,
  props: { params: Promise<{ value: string }> }
) {
  const params = await props.params;
  const actor = await actorOr401(request);
  if (actor instanceof NextResponse) return actor;
  const ioc = decodeURIComponent(params.value).trim();
  if (!ioc) {
    return NextResponse.json({ error: "invalid_ioc" }, { status: 400 });
  }

  const parsed = querySchema.safeParse(
    Object.fromEntries(request.nextUrl.searchParams)
  );
  const { limit, page } = parsed.success ? parsed.data : { limit: 25, page: 1 };

  // Determine which IOC fields could match.
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(ioc);
  const isHash = /^[0-9a-fA-F]{32,64}$/.test(ioc);
  const isUrl = ioc.startsWith("http://") || ioc.startsWith("https://");

  const iocWhere = isIp
    ? [{ ip: { contains: ioc, mode: "insensitive" as const } }]
    : isHash
    ? [{ hash: { contains: ioc, mode: "insensitive" as const } }]
    : isUrl
    ? [{ url: { contains: ioc, mode: "insensitive" as const } }]
    : [
        { url: { contains: ioc, mode: "insensitive" as const } },
        { ip: { contains: ioc, mode: "insensitive" as const } },
        { domain: { contains: ioc, mode: "insensitive" as const } },
        { hash: { contains: ioc, mode: "insensitive" as const } },
        { processName: { contains: ioc, mode: "insensitive" as const } },
        { username: { contains: ioc, mode: "insensitive" as const } },
        { hostname: { contains: ioc, mode: "insensitive" as const } },
        { commandLine: { contains: ioc, mode: "insensitive" as const } },
        { searchableText: { contains: ioc, mode: "insensitive" as const } },
      ];

  const [total, rows, stats] = await Promise.all([
    prisma.evidence.count({ where: { OR: iocWhere, ...investigationOrgWhere(actor) } }),
    prisma.evidence.findMany({
      where: { OR: iocWhere, ...investigationOrgWhere(actor) },
      select: {
        id: true,
        type: true,
        timestamp: true,
        hostname: true,
        username: true,
        url: true,
        ip: true,
        domain: true,
        hash: true,
        processName: true,
        commandLine: true,
        investigationId: true,
        investigation: { select: { id: true, title: true, hostname: true } },
        finding: { select: { id: true, findingType: true, severity: true } },
      },
      orderBy: { timestamp: "desc" },
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.evidence.aggregate({
      where: { OR: iocWhere, ...investigationOrgWhere(actor) },
      _min: { timestamp: true },
      _max: { timestamp: true },
      _count: { id: true },
    }),
  ]);

  // Distinct investigations containing this IOC.
  const investigationIds = [
    ...new Set(rows.map((r) => r.investigationId)),
  ];

  return NextResponse.json({
    ioc,
    total,
    firstSeen: stats._min.timestamp,
    lastSeen: stats._max.timestamp,
    investigationCount: investigationIds.length,
    rows,
    page,
    pages: Math.ceil(total / limit),
  });
}
