export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { deriveScopedIocSources, sourcesForValues, labelSources } from "@/lib/ioc/scope";
import { buildXlsxBuffer } from "@/lib/reports/xlsx-export";

const EXPORT_CAP = 20000;

// GET /api/ioc/export — every IocRecord matching the current filters
// (q/type/caseId, same as /api/ioc/list) as a single-sheet Excel workbook.
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  const { searchParams } = new URL(req.url);
  const q      = searchParams.get("q") ?? undefined;
  const type   = searchParams.get("type") ?? undefined;
  const caseId = searchParams.get("caseId") ?? undefined;
  const minReputationParam = searchParams.get("minReputation");
  const minReputation = minReputationParam !== null ? Number(minReputationParam) : undefined;
  const maxReputationParam = searchParams.get("maxReputation");
  const maxReputation = maxReputationParam !== null ? Number(maxReputationParam) : undefined;

  const reputationFilter: { gte?: number; lte?: number } = {};
  if (minReputation !== undefined && Number.isFinite(minReputation)) reputationFilter.gte = minReputation;
  if (maxReputation !== undefined && Number.isFinite(maxReputation)) reputationFilter.lte = maxReputation;

  const { valueFilter, sources: scopedSources, needsScoping } = await deriveScopedIocSources(actor, caseId);

  const iocs = (valueFilter && valueFilter.in.length === 0)
    ? []
    : await prisma.iocRecord.findMany({
        where: {
          ...(valueFilter ? { value: valueFilter } : {}),
          ...(q ? { value: { contains: q, mode: "insensitive" } } : {}),
          ...(type ? { type } : {}),
          ...(Object.keys(reputationFilter).length > 0 ? { reputation: reputationFilter } : {}),
        },
        include: {
          enrichments: {
            select: { provider: true, status: true, enrichedAt: true },
            orderBy: { enrichedAt: "desc" },
          },
        },
        orderBy: { createdAt: "desc" },
        take: EXPORT_CAP,
      });

  const pageSources = needsScoping ? scopedSources : await sourcesForValues(iocs.map((i) => i.value));

  const buffer = await buildXlsxBuffer([
    {
      name: "IOCs",
      columns: [
        { header: "Value", key: "value", width: 45 },
        { header: "Type", key: "type", width: 12 },
        { header: "Source", key: "sources", width: 30 },
        { header: "Reputation", key: "reputation", width: 12 },
        { header: "Threat Type", key: "threatType", width: 20 },
        { header: "Malware Family", key: "malwareFamily", width: 20 },
        { header: "Enrichment Providers", key: "enrichmentProviders", width: 30 },
        { header: "First Seen", key: "firstSeen", width: 22 },
        { header: "Created", key: "createdAt", width: 22 },
      ],
      rows: iocs.map((ioc) => ({
        value: ioc.value,
        type: ioc.type,
        sources: labelSources(pageSources.get(ioc.value), ioc.enrichments.length).join(", "),
        reputation: ioc.reputation ?? "",
        threatType: ioc.threatType ?? "",
        malwareFamily: ioc.malwareFamily ?? "",
        enrichmentProviders: ioc.enrichments.filter((e) => e.status === "ok").map((e) => e.provider).join(", "),
        firstSeen: ioc.firstSeen ? ioc.firstSeen.toISOString() : "",
        createdAt: ioc.createdAt.toISOString(),
      })),
    },
  ]);

  return new NextResponse(new Uint8Array(buffer), {
    headers: {
      "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "Content-Disposition": `attachment; filename="ioc-intelligence.xlsx"`,
      "Content-Length": String(buffer.length),
    },
  });
}
