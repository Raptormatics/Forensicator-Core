export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { computeRiskScore, riskTier } from "@/lib/hosts/risk";

// GET /api/hosts — aggregate host stats live from investigations
// Falls back gracefully even when no HostProfile rows have been synced yet.
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  const { searchParams } = new URL(req.url);
  const q = searchParams.get("q") ?? undefined;

  const orgFilter = orgWhere(actor);

  // First try HostProfile table (populated by sync)
  const profiles = await prisma.hostProfile.findMany({
    where: orgFilter,
    include: { isolationUpdatedBy: { select: { email: true, name: true } } },
    orderBy: { riskScore: "desc" },
  });

  if (profiles.length > 0) {
    const filtered = q
      ? profiles.filter((h) => {
          const lower = q.toLowerCase();
          const os = typeof h.osInfo === "object" && h.osInfo !== null
            ? String((h.osInfo as Record<string, unknown>).platform ?? "")
            : "";
          return h.hostname.toLowerCase().includes(lower) || os.toLowerCase().includes(lower) || (h.primaryUser ?? "").toLowerCase().includes(lower);
        })
      : profiles;
    const withTier = filtered.map((h) => ({ ...h, riskTier: riskTier(h.riskScore, h.criticalCount) }));
    return NextResponse.json({ hosts: withTier });
  }

  // No profiles synced yet — aggregate directly from investigations
  const investigations = await prisma.investigation.findMany({
    where: {
      ...orgFilter,
      ...(q ? { hostname: { contains: q, mode: "insensitive" } } : { hostname: { not: null } }),
    },
    select: {
      id: true,
      hostname: true,
      username: true,
      osInfo: true,
      findingCount: true,
      detectionStats: true,
      createdAt: true,
    },
    orderBy: { createdAt: "asc" },
  });

  if (investigations.length === 0) return NextResponse.json({ hosts: [] });

  const invIds = investigations.map((i) => i.id);

  // USB / persistence finding counts, batched across every matching investigation at once.
  const [usbFindings, persistenceFindings, lastIpEvidence] = await Promise.all([
    prisma.finding.findMany({
      where: { investigationId: { in: invIds }, category: { contains: "usb", mode: "insensitive" } },
      select: { investigationId: true },
    }),
    prisma.finding.findMany({
      where: {
        investigationId: { in: invIds },
        OR: [
          { category: { contains: "persist", mode: "insensitive" } },
          { category: { contains: "service",  mode: "insensitive" } },
          { category: { contains: "startup",  mode: "insensitive" } },
        ],
      },
      select: { investigationId: true },
    }),
    prisma.evidence.findMany({
      where: { investigationId: { in: invIds }, ip: { not: null } },
      select: { investigationId: true, ip: true, timestamp: true, createdAt: true },
      orderBy: [{ timestamp: "desc" }, { createdAt: "desc" }],
    }),
  ]);

  const invToHostname = new Map(investigations.map((i) => [i.id, i.hostname!]));
  function tallyByHostname(rows: { investigationId: string }[]): Map<string, number> {
    const m = new Map<string, number>();
    for (const r of rows) {
      const host = invToHostname.get(r.investigationId);
      if (!host) continue;
      m.set(host, (m.get(host) ?? 0) + 1);
    }
    return m;
  }
  const usbByHost = tallyByHostname(usbFindings);
  const persistenceByHost = tallyByHostname(persistenceFindings);

  // Evidence rows are pre-sorted most-recent-first, so the first ip seen per hostname wins.
  const lastIpByHost = new Map<string, string>();
  for (const e of lastIpEvidence) {
    const host = invToHostname.get(e.investigationId);
    if (!host || lastIpByHost.has(host) || !e.ip) continue;
    lastIpByHost.set(host, e.ip);
  }

  // Group by hostname
  type AggHost = {
    hostname: string;
    osInfo: unknown;
    investigationCount: number;
    findingCount: number;
    criticalCount: number;
    highCount: number;
    iocMatchCount: number;
    firstSeen: string;
    lastSeen: string;
    userCounts: Map<string, { count: number; lastSeen: string }>;
  };

  const grouped = new Map<string, AggHost>();

  for (const inv of investigations) {
    if (!inv.hostname) continue;
    const ds = inv.detectionStats as Record<string, number> | null;
    let existing = grouped.get(inv.hostname);
    if (!existing) {
      existing = {
        hostname: inv.hostname, osInfo: inv.osInfo,
        investigationCount: 0, findingCount: 0, criticalCount: 0, highCount: 0, iocMatchCount: 0,
        firstSeen: inv.createdAt.toISOString(), lastSeen: inv.createdAt.toISOString(),
        userCounts: new Map(),
      };
      grouped.set(inv.hostname, existing);
    }
    existing.investigationCount++;
    existing.findingCount += inv.findingCount ?? 0;
    existing.criticalCount += ds?.critical_detections ?? 0;
    existing.highCount += ds?.high_detections ?? 0;
    existing.iocMatchCount += ds?.ioc_detections ?? 0;
    existing.lastSeen = inv.createdAt.toISOString();
    existing.osInfo = inv.osInfo ?? existing.osInfo;
    if (inv.username) {
      const cur = existing.userCounts.get(inv.username) ?? { count: 0, lastSeen: inv.createdAt.toISOString() };
      cur.count++;
      if (inv.createdAt.toISOString() > cur.lastSeen) cur.lastSeen = inv.createdAt.toISOString();
      existing.userCounts.set(inv.username, cur);
    }
  }

  const hosts = Array.from(grouped.values()).map((h) => {
    const usbActivity = usbByHost.get(h.hostname) ?? 0;
    const persistenceEvents = persistenceByHost.get(h.hostname) ?? 0;
    const riskScore = computeRiskScore({
      criticalCount: h.criticalCount, highCount: h.highCount, iocMatchCount: h.iocMatchCount,
      persistenceEvents, usbActivity,
    });
    let primaryUser: string | null = null;
    let best: { count: number; lastSeen: string } | null = null;
    for (const [user, stat] of h.userCounts) {
      if (!best || stat.count > best.count || (stat.count === best.count && stat.lastSeen > best.lastSeen)) {
        best = stat; primaryUser = user;
      }
    }
    return {
      hostname: h.hostname, osInfo: h.osInfo,
      investigationCount: h.investigationCount, findingCount: h.findingCount,
      criticalCount: h.criticalCount, highCount: h.highCount, iocMatchCount: h.iocMatchCount,
      usbActivity, persistenceEvents,
      riskScore, riskTier: riskTier(riskScore, h.criticalCount),
      primaryUser, lastKnownIp: lastIpByHost.get(h.hostname) ?? null,
      isolationStatus: "active" as const, isolationNote: null, isolationUpdatedAt: null, isolationUpdatedBy: null,
      firstSeen: h.firstSeen, lastSeen: h.lastSeen,
    };
  }).sort((a, b) => b.riskScore - a.riskScore || b.findingCount - a.findingCount);

  return NextResponse.json({ hosts });
}
