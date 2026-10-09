export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { computeRiskScore, riskTier } from "@/lib/hosts/risk";

type Params = { params: Promise<{ hostname: string }> };

const ISOLATION_STATUSES = new Set(["active", "quarantined", "offline"]);

/** Best-effort extraction from Finding.data.evidence[] rows produced by the
 * collector's network-adapter/IP-config artifacts. Real collected values
 * only — returns null rather than guessing when nothing is present. */
function extractFirstEvidenceField(findings: { data: unknown }[], key: string): string | null {
  for (const f of findings) {
    const data = f.data as Record<string, unknown> | null;
    const evidence = Array.isArray(data?.evidence) ? (data!.evidence as Record<string, unknown>[]) : [];
    for (const row of evidence) {
      const val = row?.[key];
      if (typeof val === "string" && val.trim()) return val.trim();
    }
  }
  return null;
}

export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  const hostname = decodeURIComponent(params.hostname);
  const orgFilter = orgWhere(actor);

  const investigations = await prisma.investigation.findMany({
    where: { hostname, ...orgFilter },
    select: {
      id: true, hostname: true, title: true, status: true, aiStatus: true, findingCount: true,
      detectionStats: true, osInfo: true, username: true, createdAt: true,
      metadata: true, organizationId: true, caseId: true,
      case: { select: { id: true, title: true, caseSeq: true, status: true, severity: true } },
      attackPaths: { select: { id: true, status: true }, take: 1 },
    },
    // Oldest first — this order is what the delta computation below relies on.
    orderBy: { createdAt: "asc" },
  });

  if (investigations.length === 0)
    return NextResponse.json({ error: "Not found" }, { status: 404 });

  const invIds = investigations.map((i) => i.id);

  // Isolation tracking (and OS/tags fallback) still comes from the synced
  // HostProfile row when one exists — everything else below is always
  // computed live from the investigations just fetched, so the KPI cards
  // and the table below can never disagree with each other.
  const profile = await prisma.hostProfile.findFirst({
    where: { hostname, ...orgFilter },
    include: { isolationUpdatedBy: { select: { email: true, name: true } } },
  });

  const ds = (inv: (typeof investigations)[0]) => (inv.detectionStats as Record<string, number> | null) ?? {};
  const criticalCount = investigations.reduce((s, i) => s + (ds(i).critical_detections ?? 0), 0);
  const highCount     = investigations.reduce((s, i) => s + (ds(i).high_detections ?? 0), 0);
  const iocMatchCount = investigations.reduce((s, i) => s + (ds(i).ioc_detections ?? 0), 0);
  const findingCount  = investigations.reduce((s, i) => s + (i.findingCount ?? 0), 0);

  const [usbCount, persistenceCount, lastIpEvidence, networkFindings] = await Promise.all([
    prisma.finding.count({ where: { investigationId: { in: invIds }, category: { contains: "usb", mode: "insensitive" } } }),
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
    // Network adapter / IP config findings carry MAC + domain in their raw
    // evidence rows — there's no structured column for either, so this is
    // the only real source. Most-recent investigations first.
    prisma.finding.findMany({
      where: { investigationId: { in: invIds }, category: "Network Activity" },
      select: { data: true },
      orderBy: { createdAt: "desc" },
      take: 20,
    }),
  ]);

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

  const macAddress = extractFirstEvidenceField(networkFindings, "mac_address");
  const domain = extractFirstEvidenceField(networkFindings, "dns_domain");

  const riskScore = computeRiskScore({ criticalCount, highCount, iocMatchCount, persistenceEvents: persistenceCount, usbActivity: usbCount });

  const hostOut = {
    hostname,
    firstSeen: investigations[0].createdAt,
    lastSeen: investigations[investigations.length - 1].createdAt,
    investigationCount: investigations.length,
    findingCount, criticalCount, highCount, iocMatchCount,
    usbActivity: usbCount,
    persistenceEvents: persistenceCount,
    riskScore, riskTier: riskTier(riskScore, criticalCount),
    osInfo: investigations[investigations.length - 1].osInfo ?? null,
    tags: profile?.tags ?? [],
    primaryUser,
    lastKnownIp: lastIpEvidence?.ip ?? null,
    macAddress, domain,
    isolationStatus: profile?.isolationStatus ?? "active",
    isolationNote: profile?.isolationNote ?? null,
    isolationUpdatedAt: profile?.isolationUpdatedAt ?? null,
    isolationUpdatedBy: profile?.isolationUpdatedBy ?? null,
    organizationId: investigations[0].organizationId ?? null,
  };

  // Recent cases this host's investigations belong to (via the direct Investigation.caseId FK).
  const caseById = new Map<string, { id: string; title: string; caseSeq: number; status: string; severity: string }>();
  for (const inv of investigations) if (inv.case) caseById.set(inv.case.id, inv.case);
  const cases = Array.from(caseById.values());

  // Per-investigation delta vs. the previous (chronologically earlier)
  // upload for this same host — surfaces whether the latest collection
  // actually found anything new, or is just re-confirming the same state.
  const investigationsOut = investigations.map((inv, i) => {
    const prev = i > 0 ? investigations[i - 1] : null;
    const iocCount = ds(inv).ioc_detections ?? 0;
    const prevIocCount = prev ? (ds(prev).ioc_detections ?? 0) : null;
    return {
      id: inv.id,
      hostname: inv.hostname,
      title: inv.title,
      status: inv.status,
      aiStatus: inv.aiStatus,
      createdAt: inv.createdAt,
      findingCount: inv.findingCount,
      case: inv.case,
      hasAttackPath: inv.attackPaths.length > 0 && inv.attackPaths[0].status === "ready",
      deltaFindings: prev ? (inv.findingCount ?? 0) - (prev.findingCount ?? 0) : null,
      deltaIocs: prev ? iocCount - prevIocCount! : null,
    };
  }).reverse(); // newest first for display, matching the previous UI convention

  return NextResponse.json({ host: hostOut, investigations: investigationsOut, cases });
}

// PATCH /api/hosts/[hostname] — update the analyst-tracked containment
// status. This platform has no EDR/agent integration, so this only records
// that containment action was taken elsewhere; it does not isolate anything.
export async function PATCH(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  const hostname = decodeURIComponent(params.hostname);
  const body = await req.json().catch(() => ({}));
  const isolationStatus = typeof body.isolationStatus === "string" ? body.isolationStatus : undefined;
  const isolationNote = typeof body.isolationNote === "string" ? body.isolationNote.trim() || null : undefined;
  if (!isolationStatus || !ISOLATION_STATUSES.has(isolationStatus)) {
    return NextResponse.json({ error: "invalid_status", message: `isolationStatus must be one of: ${Array.from(ISOLATION_STATUSES).join(", ")}` }, { status: 400 });
  }

  const orgFilter = orgWhere(actor);
  const investigations = await prisma.investigation.findMany({
    where: { hostname, ...orgFilter }, select: { organizationId: true }, take: 1,
  });
  if (investigations.length === 0) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const host = await prisma.hostProfile.upsert({
    where: { hostname },
    update: {
      isolationStatus,
      ...(isolationNote !== undefined ? { isolationNote } : {}),
      isolationUpdatedAt: new Date(),
      isolationUpdatedById: actor.id,
    },
    create: {
      hostname,
      firstSeen: new Date(),
      lastSeen: new Date(),
      isolationStatus,
      isolationNote: isolationNote ?? null,
      isolationUpdatedAt: new Date(),
      isolationUpdatedById: actor.id,
      organizationId: investigations[0].organizationId ?? null,
    },
  });

  return NextResponse.json({ host });
}
