import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { notArchived } from "@/lib/cases/archive";
import { orgWhere } from "@/lib/auth/api-guard";
import { actorOr401 } from "@/lib/auth/org-access";

const querySchema = z.object({
  q: z.string().min(1).max(500),
  limit: z.coerce.number().int().min(1).max(50).default(10),
  archived: z.enum(["include", "exclude"]).default("exclude"),
});

export async function GET(request: NextRequest) {
  const actor = await actorOr401(request);
  if (actor instanceof NextResponse) return actor;
  const params = Object.fromEntries(request.nextUrl.searchParams);
  const result = querySchema.safeParse(params);

  if (!result.success) {
    return NextResponse.json(
      { error: "invalid_query", message: "Provide a non-empty search query (q)." },
      { status: 400 }
    );
  }

  const { q, limit, archived } = result.data;
  // Archived investigations are left out unless ?archived=include.
  // Only the caller's organizations; archived investigations unless asked for.
  const org = orgWhere(actor);
  const invScope = { AND: [org, ...(archived === "include" ? [] : [notArchived()])] };
  const childScope = { investigation: { ...org, ...(archived === "include" ? {} : notArchived()) } };
  const pattern = `%${q}%`;

  const [investigations, findings, evidenceRows] = await Promise.all([
    // Investigations — match title, hostname, tags
    prisma.investigation.findMany({
      where: {
        ...invScope,
        OR: [
          { title: { contains: q, mode: "insensitive" } },
          { hostname: { contains: q, mode: "insensitive" } },
          { username: { contains: q, mode: "insensitive" } },
          { tags: { has: q } },
        ],
      },
      select: {
        id: true,
        title: true,
        hostname: true,
        username: true,
        tags: true,
        status: true,
        osInfo: true,
        createdAt: true,
      },
      take: limit,
    }),

    // Findings — match searchText, findingType, category
    prisma.finding.findMany({
      where: {
        ...childScope,
        OR: [
          { searchText: { contains: q, mode: "insensitive" } },
          { findingType: { contains: q, mode: "insensitive" } },
          { category: { contains: q, mode: "insensitive" } },
          { findingId: { contains: q, mode: "insensitive" } },
        ],
      },
      select: {
        id: true,
        findingId: true,
        findingType: true,
        category: true,
        severity: true,
        riskScore: true,
        hostName: true,
        sourceCategory: true,
        investigationId: true,
        investigation: { select: { id: true, title: true } },
      },
      take: limit,
    }),

    // Evidence — IOC pivoting + full text
    prisma.evidence.findMany({
      where: {
        ...childScope,
        OR: [
          { url: { contains: q, mode: "insensitive" } },
          { ip: { contains: q, mode: "insensitive" } },
          { domain: { contains: q, mode: "insensitive" } },
          { hash: { contains: q, mode: "insensitive" } },
          { processName: { contains: q, mode: "insensitive" } },
          { commandLine: { contains: q, mode: "insensitive" } },
          { username: { contains: q, mode: "insensitive" } },
          { hostname: { contains: q, mode: "insensitive" } },
          { searchableText: { contains: q, mode: "insensitive" } },
        ],
      },
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
        investigationId: true,
        findingId: true,
        investigation: { select: { id: true, title: true } },
      },
      orderBy: { timestamp: "desc" },
      take: limit,
    }),
  ]);

  return NextResponse.json({
    query: q,
    investigations,
    findings,
    evidence: evidenceRows,
    counts: {
      investigations: investigations.length,
      findings: findings.length,
      evidence: evidenceRows.length,
    },
  });
}
