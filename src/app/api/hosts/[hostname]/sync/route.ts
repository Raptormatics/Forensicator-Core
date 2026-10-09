export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { computeRiskScore } from "@/lib/hosts/risk";

type Params = { params: Promise<{ hostname: string }> };

/**
 * POST /api/hosts/[hostname]/sync
 * Upserts the HostProfile by aggregating data from all investigations
 * that match this hostname (scoped to the actor's org).
 */
export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  const hostname = decodeURIComponent(params.hostname);
  const orgFilter = orgWhere(actor);

  const investigations = await prisma.investigation.findMany({
    where: { hostname, ...orgFilter },
    orderBy: { createdAt: "asc" },
    select: {
      id: true,
      createdAt: true,
      findingCount: true,
      detectionStats: true,
      osInfo: true,
      username: true,
      organizationId: true,
    },
  });

  if (investigations.length === 0)
    return NextResponse.json({ error: "No investigations found for this hostname" }, { status: 404 });

  // Aggregate stats
  const firstSeen   = investigations[0].createdAt;
  const lastSeen    = investigations[investigations.length - 1].createdAt;
  const invCount    = investigations.length;
  const findingSum  = investigations.reduce((s, i) => s + (i.findingCount ?? 0), 0);
  // Derive critical/high/ioc counts from detectionStats JSON
  function getDStat(inv: (typeof investigations)[0], key: string): number {
    const ds = inv.detectionStats as Record<string, number> | null;
    return ds?.[key] ?? 0;
  }
  const critSum  = investigations.reduce((s, i) => s + getDStat(i, "critical_detections"), 0);
  const highSum  = investigations.reduce((s, i) => s + getDStat(i, "high_detections"), 0);
  const iocSum   = investigations.reduce((s, i) => s + getDStat(i, "ioc_detections"), 0);
  const osInfo   = investigations[investigations.length - 1].osInfo;

  const invIds = investigations.map((i) => i.id);

  // Count USB + persistence findings, and derive the most recent known IP.
  const [usbCount, persistenceCount, lastIpEvidence] = await Promise.all([
    prisma.finding.count({
      where: { investigationId: { in: invIds }, category: { contains: "usb", mode: "insensitive" } },
    }),
    prisma.finding.count({
      where: {
        investigationId: { in: invIds },
        OR: [
          { category: { contains: "persist", mode: "insensitive" } },
          { category: { contains: "service",  mode: "insensitive" } },
          { category: { contains: "startup",  mode: "insensitive" } },
        ],
      },
    }),
    prisma.evidence.findFirst({
      where: { investigationId: { in: invIds }, ip: { not: null } },
      orderBy: [{ timestamp: "desc" }, { createdAt: "desc" }],
      select: { ip: true },
    }),
  ]);

  // Most frequent username across this host's investigations, tie-broken by most recent.
  let primaryUser: string | null = null;
  const userCounts = new Map<string, { count: number; lastSeen: Date }>();
  for (const inv of investigations) {
    if (!inv.username) continue;
    const cur = userCounts.get(inv.username) ?? { count: 0, lastSeen: inv.createdAt };
    cur.count++;
    if (inv.createdAt > cur.lastSeen) cur.lastSeen = inv.createdAt;
    userCounts.set(inv.username, cur);
  }
  let best: { count: number; lastSeen: Date } | null = null;
  for (const [user, stat] of userCounts) {
    if (!best || stat.count > best.count || (stat.count === best.count && stat.lastSeen > best.lastSeen)) {
      best = stat; primaryUser = user;
    }
  }

  const riskScore = computeRiskScore({ criticalCount: critSum, highCount: highSum, iocMatchCount: iocSum, persistenceEvents: persistenceCount, usbActivity: usbCount });
  // Derive the host's org from its investigations, not the caller's identity
  // (a platform_admin syncing on another org's behalf shouldn't reassign it).
  const organizationId = investigations[0].organizationId ?? null;

  const profile = await prisma.hostProfile.upsert({
    where: { hostname },
    update: {
      lastSeen,
      investigationCount: invCount,
      findingCount: findingSum,
      criticalCount: critSum,
      highCount: highSum,
      iocMatchCount: iocSum,
      usbActivity: usbCount,
      persistenceEvents: persistenceCount,
      riskScore,
      osInfo: osInfo ?? undefined,
      primaryUser,
      lastKnownIp: lastIpEvidence?.ip ?? null,
      organizationId,
    },
    create: {
      hostname,
      firstSeen,
      lastSeen,
      investigationCount: invCount,
      findingCount: findingSum,
      criticalCount: critSum,
      highCount: highSum,
      iocMatchCount: iocSum,
      usbActivity: usbCount,
      persistenceEvents: persistenceCount,
      riskScore,
      osInfo: osInfo ?? undefined,
      primaryUser,
      lastKnownIp: lastIpEvidence?.ip ?? null,
      organizationId,
    },
  });

  return NextResponse.json({ profile });
}
