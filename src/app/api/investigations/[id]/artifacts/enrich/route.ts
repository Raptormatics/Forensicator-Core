export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/investigations/[id]/artifacts/enrich — re-scans this
 * investigation's already-persisted Evidence rows (optionally filtered to
 * one artifact type) for ip/url/domain/hash values, upserts them into the
 * global IocRecord table, and auto-enriches whichever ones are genuinely
 * new (same free-feed + queued-live-lookup split as a fresh upload — see
 * autoEnrichNewIocs()). Backs the "Enrich <type>" / "Enrich All Artifacts"
 * buttons on the Artifact Explorer.
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { autoEnrichNewIocs, type NewIocRecord } from "@/lib/intelligence/auto-enrich";

const bodySchema = z.object({ type: z.string().optional() });

// Evidence rows examined per call — mirrors the per-upload enrichment cap
// elsewhere in this codebase; an investigation with more rows than this
// just needs the button pressed again (the response's `truncated` flag
// says so).
const SCAN_CAP = 5000;

export async function POST(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(request); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const investigation = await prisma.investigation.findFirst({
    where: { id: params.id, ...orgWhere(actor) },
    select: { id: true, organizationId: true },
  });
  if (!investigation) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const parsed = bodySchema.safeParse(await request.json().catch(() => ({})));
  const type = parsed.success ? parsed.data.type : undefined;

  const rows = await prisma.evidence.findMany({
    where: {
      investigationId: params.id,
      ...(type ? { type: { equals: type, mode: "insensitive" as const } } : {}),
    },
    select: { ip: true, url: true, domain: true, hash: true },
    take: SCAN_CAP,
  });

  const truncated = rows.length === SCAN_CAP;

  // Some collector-supplied "url" fields are actually bare hostnames (no
  // scheme) — classifying those as type "url" anyway sends a malformed
  // value to URL-specific provider endpoints (URLhaus's /v1/url/ expects a
  // real URL, not a hostname). Reclassify as a domain instead — same fix
  // as investigation-ioc-extract.ts's upload-time path.
  const URL_SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

  const values = new Map<string, "ip" | "hash" | "url" | "domain">();
  for (const row of rows) {
    if (row.ip) values.set(row.ip, "ip");
    if (row.domain) values.set(row.domain, "domain");
    if (row.url) {
      const u = row.url.slice(0, 500); // Postgres btree row-size guard, same as upload-time extraction
      values.set(u, URL_SCHEME_RE.test(u) ? "url" : "domain");
    }
    if (row.hash) values.set(row.hash, "hash");
  }

  const now = new Date();
  const newIocRecords: NewIocRecord[] = [];
  for (const [value, iocType] of values.entries()) {
    try {
      const rec = await prisma.iocRecord.upsert({
        where: { value },
        create: { value, type: iocType, firstSeen: now, lastSeen: now },
        update: { lastSeen: now },
      });
      if (rec.firstSeen?.getTime() === now.getTime()) {
        newIocRecords.push({ id: rec.id, value: rec.value, type: iocType });
      }
    } catch (err) {
      console.warn("[artifacts/enrich] IocRecord upsert skipped:", value, err instanceof Error ? err.message : err);
    }
  }

  const { feedMatches, queued } = await autoEnrichNewIocs(newIocRecords, investigation.organizationId ?? undefined);

  return NextResponse.json({
    evidenceScanned: rows.length,
    uniqueIocs: values.size,
    newRecords: newIocRecords.length,
    feedMatches,
    queued,
    truncated,
  });
}
