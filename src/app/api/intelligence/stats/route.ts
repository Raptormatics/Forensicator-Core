export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { listOrgProviderStatus } from "@/lib/intelligence/org-providers";

export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  // Scope IOC queries to the org's investigations via Evidence
  const scope = orgWhere(actor);
  let iocValueWhere: { value?: { in: string[] } } = {};
  if (actor.role !== "platform_admin") {
    const orgInvestigationIds = await prisma.investigation.findMany({
      where: scope, select: { id: true },
    }).then((rows) => rows.map((r) => r.id));

    if (orgInvestigationIds.length === 0) {
      return NextResponse.json({
        totalIocs: 0, enrichedIocs: 0, pendingIocs: 0,
        maliciousCount: 0, suspiciousCount: 0, cleanCount: 0,
        byProvider: {}, recentEnrichments: [],
        providerStatus: await buildProviderStatus(actor.organizationIds[0]),
      });
    }

    const vals = await prisma.evidence.findMany({
      where: {
        investigationId: { in: orgInvestigationIds },
        OR: [{ ip: { not: null } }, { url: { not: null } }, { hash: { not: null } }, { domain: { not: null } }],
      },
      select: { ip: true, url: true, hash: true, domain: true },
    }).then((rows) => {
      const s = new Set<string>();
      for (const r of rows) {
        if (r.ip)     s.add(r.ip);
        if (r.url)    s.add(r.url);
        if (r.hash)   s.add(r.hash);
        if (r.domain) s.add(r.domain);
      }
      return Array.from(s);
    });

    if (vals.length === 0) {
      return NextResponse.json({
        totalIocs: 0, enrichedIocs: 0, pendingIocs: 0,
        maliciousCount: 0, suspiciousCount: 0, cleanCount: 0,
        byProvider: {}, recentEnrichments: [],
        providerStatus: await buildProviderStatus(actor.organizationIds[0]),
      });
    }
    iocValueWhere = { value: { in: vals } };
  }

  const sp = req.nextUrl.searchParams;
  const logProvider = sp.get("provider") || undefined;
  const logStatus = sp.get("status") || undefined; // "ok" | "error" | "not_found" | "pending"
  const logLimit = Math.min(100, Math.max(1, Number(sp.get("logLimit") ?? 20) || 20));

  const [totalIocs, enrichedIocs, verdictCounts, allEnrichments, recentEnrichmentsRaw] = await Promise.all([
    prisma.iocRecord.count({ where: iocValueWhere }),
    // Distinct IocRecords with at least one enrichment attempt of any status —
    // computed as its own count query (not derived from a capped recent-log
    // fetch) so it can never fall out of sync with the malicious/suspicious
    // counts below, which are also uncapped.
    prisma.iocRecord.count({ where: { ...iocValueWhere, enrichments: { some: {} } } }),
    // Verdict thresholds match the IOC Intelligence / Dashboard pages' own
    // convention: reputation >= 70 malicious, >= 40 suspicious, else clean.
    // Only counts IocRecords that have actually been enriched (reputation
    // is set) — un-enriched records are neither clean nor malicious, just unknown.
    prisma.iocRecord.groupBy({
      by: ["reputation"],
      where: { ...iocValueWhere, reputation: { not: null } },
      _count: true,
    }),
    // Every enrichment row (uncapped) — used only for the provider-breakdown
    // totals, which must reflect all enrichment activity, not just the most
    // recent 500 events.
    prisma.iocEnrichment.findMany({
      where: Object.keys(iocValueWhere).length > 0 ? { ioc: iocValueWhere } : {},
      select: { provider: true, status: true, ioc: { select: { reputation: true } } },
    }),
    // The "Recent Enrichments" log itself — capped and independently
    // filterable by provider/status via query params.
    prisma.iocEnrichment.findMany({
      where: {
        ...(Object.keys(iocValueWhere).length > 0 ? { ioc: iocValueWhere } : {}),
        ...(logProvider ? { provider: logProvider } : {}),
        ...(logStatus ? { status: logStatus } : {}),
      },
      select: { provider: true, status: true, enrichedAt: true, ioc: { select: { value: true, type: true, reputation: true } } },
      orderBy: { enrichedAt: "desc" },
      take: logLimit,
    }),
  ]);

  let maliciousCount = 0, suspiciousCount = 0, cleanCount = 0;
  for (const row of verdictCounts) {
    const rep = row.reputation ?? 0;
    if (rep >= 70) maliciousCount += row._count;
    else if (rep >= 40) suspiciousCount += row._count;
    else cleanCount += row._count;
  }

  const byProvider: Record<string, { total: number; malicious: number; suspicious: number }> = {};

  for (const e of allEnrichments) {
    if (!byProvider[e.provider]) byProvider[e.provider] = { total: 0, malicious: 0, suspicious: 0 };
    if (e.status !== "ok") continue;
    byProvider[e.provider].total++;
    const rep = e.ioc.reputation;
    if (rep !== null && rep >= 70) byProvider[e.provider].malicious++;
    else if (rep !== null && rep >= 40) byProvider[e.provider].suspicious++;
  }

  const recentFormatted = recentEnrichmentsRaw.map((e) => ({
    iocValue: e.ioc.value,
    iocType:  e.ioc.type,
    provider: e.provider,
    status:   e.status,
    verdict:  e.status === "ok" ? "enriched" : e.status,
    score:    null as number | null,
    createdAt: e.enrichedAt ?? new Date().toISOString(),
  }));

  const providerStatus = await buildProviderStatus(actor.organizationIds[0]);

  return NextResponse.json({
    totalIocs,
    enrichedIocs,
    pendingIocs: totalIocs - enrichedIocs,
    maliciousCount,
    suspiciousCount,
    cleanCount,
    byProvider,
    recentEnrichments: recentFormatted,
    providerStatus,
  });
}

const LABEL: Record<string, string> = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  urlhaus: "URLhaus",
  threatfox: "ThreatFox",
  malwarebazaar: "MalwareBazaar",
  otx: "OTX AlienVault",
};

const SUPPORTED_TYPES: Record<string, string[]> = {
  virustotal: ["ip", "hash", "url", "domain"],
  abuseipdb: ["ip", "url (IP host)"],
  urlhaus: ["url", "domain", "hash"],
  threatfox: ["ip", "hash", "url", "domain"],
  malwarebazaar: ["hash"],
  otx: ["ip", "hash", "url", "domain"],
};

/** Full status for every provider (keyed and keyless) — never an empty list, regardless of enrichment activity. */
async function buildProviderStatus(organizationId: string | undefined) {
  const providers = await listOrgProviderStatus(organizationId);
  return providers.map((p) => {
    const active = p.enabled && (!p.requiresKey || p.configured || p.usingGlobalFallback);
    const statusText = !p.enabled
      ? "Disabled"
      : p.requiresKey
        ? p.configured
          ? "Active (org key)"
          : p.usingGlobalFallback
            ? "Active (deployment default)"
            : "No API key"
        : "Active";
    return {
      name: p.provider,
      label: LABEL[p.provider] ?? p.provider,
      configured: active,
      enabled: p.enabled,
      requiresKey: p.requiresKey,
      statusText,
      supportedTypes: SUPPORTED_TYPES[p.provider] ?? [],
    };
  });
}
