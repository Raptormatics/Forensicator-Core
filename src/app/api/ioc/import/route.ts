export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { getEnrichmentQueue } from "@/lib/jobs/queues";

const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5MB
const MAX_LINES = 20_000;
// Bulk-queuing enrichment is opt-in; still capped so a huge list can't burn
// through a paid provider's quota in one accidental upload.
const MAX_ENRICH_QUEUE = 500;

const RE_IPV4    = /^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$/;
const RE_URL     = /^https?:\/\/\S+$/i;
const RE_MD5     = /^[a-fA-F0-9]{32}$/;
const RE_SHA1    = /^[a-fA-F0-9]{40}$/;
const RE_SHA256  = /^[a-fA-F0-9]{64}$/;
// Bare hostname, no scheme required — e.g. "evil.com", "c2.malicious-domain.co.uk".
// The alphabetic-only TLD requirement keeps this from ever matching an IPv4
// address (already handled above), so branch order here doesn't matter.
const RE_DOMAIN  = /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

function classify(line: string): { type: "ip" | "hash" | "url" | "domain"; value: string } | null {
  if (RE_URL.test(line)) return { type: "url", value: line };
  if (RE_IPV4.test(line)) return { type: "ip", value: line };
  if (RE_MD5.test(line) || RE_SHA1.test(line) || RE_SHA256.test(line)) return { type: "hash", value: line.toLowerCase() };
  if (RE_DOMAIN.test(line)) return { type: "domain", value: line.toLowerCase() };
  return null;
}

/**
 * POST /api/ioc/import — bulk-add IOCs (hash/URL/IPv4/domain, one per line)
 * from an uploaded plaintext file. Lines starting with # and blank lines are
 * ignored; anything that doesn't parse as one of those four types is
 * reported back as skipped rather than silently dropped.
 */
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const formData = await req.formData();
  const file = formData.get("file");
  if (!(file instanceof File)) {
    return NextResponse.json({ error: "missing_file", message: "Upload a .txt file in the form field named file." }, { status: 400 });
  }
  if (file.size > MAX_FILE_BYTES) {
    return NextResponse.json({ error: "file_too_large", message: "File is limited to 5MB." }, { status: 413 });
  }
  const queueEnrichment = formData.get("queueEnrichment") === "true";

  const text = await file.text();
  const rawLines = text.split(/\r?\n/);
  const truncated = rawLines.length > MAX_LINES;
  const lines = rawLines.slice(0, MAX_LINES);

  const seen = new Set<string>();
  const hits: { type: "ip" | "hash" | "url" | "domain"; value: string }[] = [];
  let skipped = 0;
  const skippedSamples: string[] = [];

  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const hit = classify(line);
    if (!hit) {
      skipped++;
      if (skippedSamples.length < 10) skippedSamples.push(line.slice(0, 80));
      continue;
    }
    const key = `${hit.type}::${hit.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    hits.push(hit);
  }

  const values = hits.map((h) => h.value);
  const existingRecords = values.length > 0
    ? await prisma.iocRecord.findMany({ where: { value: { in: values } }, select: { value: true } })
    : [];
  const existingSet = new Set(existingRecords.map((r) => r.value));
  const newHits = hits.filter((h) => !existingSet.has(h.value));

  if (newHits.length > 0) {
    await prisma.iocRecord.createMany({
      data: newHits.map((h) => ({ value: h.value, type: h.type })),
      skipDuplicates: true,
    });
  }

  let queuedCount = 0;
  if (queueEnrichment && newHits.length > 0) {
    const toQueue = newHits.slice(0, MAX_ENRICH_QUEUE);
    const typeByValue = new Map(toQueue.map((h) => [h.value, h.type]));
    const created = await prisma.iocRecord.findMany({
      where: { value: { in: toQueue.map((h) => h.value) } },
      select: { id: true, value: true },
    });
    const queue = getEnrichmentQueue();
    for (const record of created) {
      const type = typeByValue.get(record.value);
      if (!type) continue;
      const job = await queue.add("enrich", {
        iocRecordId: record.id, value: record.value, type,
        organizationId: actor.organizationIds[0],
      });
      await prisma.iocRecord.update({ where: { id: record.id }, data: { enrichJobId: job.id ?? null } });
      queuedCount++;
    }
  }

  await prisma.activityLog.create({
    data: {
      userId: actor.id,
      action: "ioc_import",
      entityType: "ioc",
      entityId: "bulk",
      metadata: {
        filename: file.name, added: newHits.length, existing: hits.length - newHits.length,
        skipped, queuedEnrichment: queuedCount,
      } as never,
    },
  });

  return NextResponse.json({
    total: hits.length,
    added: newHits.length,
    existing: hits.length - newHits.length,
    skipped,
    skippedSamples,
    queuedEnrichment: queuedCount,
    truncated,
  });
}
