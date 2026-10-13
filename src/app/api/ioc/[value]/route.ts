/**
 * GET /api/ioc/[value] — full IOC record with enrichment results.
 * PATCH /api/ioc/[value] — analyst-tracked blocklist recommendation.
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { deriveScopedIocSources, sourcesForValues, labelSources } from "@/lib/ioc/scope";

export async function GET(
  req: NextRequest,
  props: { params: Promise<{ value: string }> }
) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const value = decodeURIComponent(params.value);
  const caseId = req.nextUrl.searchParams.get("caseId") ?? undefined;

  const record = await prisma.iocRecord.findUnique({
    where: { value },
    include: {
      enrichments: {
        orderBy: { enrichedAt: "desc" },
      },
    },
  });

  if (!record) return NextResponse.json({ error: "not_found" }, { status: 404 });

  // Count occurrences across evidence
  const [evidenceHits, investigations] = await Promise.all([
    prisma.evidence.count({
      where: {
        OR: [
          { ip: value },
          { hash: value },
          { url: value },
          { domain: value },
        ],
      },
    }),
    prisma.evidence.findMany({
      where: {
        OR: [{ ip: value }, { hash: value }, { url: value }, { domain: value }],
      },
      select: { investigationId: true },
      distinct: ["investigationId"],
    }),
  ]);

  // "Seen via" sources — case-scoped when caseId is given (consistent with
  // the list/export routes), otherwise the full unscoped breakdown. The
  // enrichment data above (record.reputation/threatType/etc.) stays
  // unscoped either way — that's third-party threat intel about the
  // indicator itself, not case-crossing observational data.
  const sourcesMap = caseId
    ? (await deriveScopedIocSources(actor, caseId)).sources
    : await sourcesForValues([value]);
  const sources = labelSources(sourcesMap.get(value), record.enrichments.length);

  return NextResponse.json({
    record,
    sources,
    stats: {
      evidenceHits,
      investigationCount: investigations.length,
    },
  });
}

// PATCH /api/ioc/[value] — toggle the "Add to Blocklist" recommendation.
// This platform has no firewall/proxy integration to actually enforce a
// block — same manual-tracking convention as HostProfile.isolationStatus.
export async function PATCH(req: NextRequest, props: { params: Promise<{ value: string }> }) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const value = decodeURIComponent(params.value);
  const body = await req.json().catch(() => ({}));
  const blocklisted = typeof body.blocklisted === "boolean" ? body.blocklisted : undefined;
  if (blocklisted === undefined) {
    return NextResponse.json({ error: "invalid_params", message: "blocklisted (boolean) is required" }, { status: 400 });
  }

  try {
    const record = await prisma.iocRecord.update({
      where: { value },
      data: blocklisted
        ? { blocklisted: true, blocklistedAt: new Date(), blocklistedById: actor.id }
        : { blocklisted: false, blocklistedAt: null, blocklistedById: null },
    });
    return NextResponse.json({ record });
  } catch {
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  }
}
