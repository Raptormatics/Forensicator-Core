/**
 * Local cache of the URLhaus "recent" bulk feed (v2 export, needs an
 * abuse.ch Auth-Key — see abuse-ch-export.ts). Unlike URLHausProvider
 * (per-value API lookup, rate-limited), matching against this local table is
 * a plain indexed query — safe to run automatically against every extracted
 * URL from every upload, with no external call and no rate-limit risk.
 */
import { prisma } from "@/lib/db/prisma";
import { parseCsvLine } from "./abuse-ch-csv";
import { fetchAbuseChExport, chunk } from "./abuse-ch-export";

export type UrlhausFeedRow = {
  urlhausId: string;
  url: string;
  urlStatus: string | null;
  threat: string | null;
  tags: string[];
  urlhausLink: string | null;
  reporter: string | null;
  dateAdded: Date | null;
};

/** Parses URLhaus's recent.csv format (same columns as the retired csv_recent): id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter */
export function parseUrlhausCsv(text: string): UrlhausFeedRow[] {
  const rows: UrlhausFeedRow[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const fields = parseCsvLine(trimmed);
    if (fields.length < 9) continue;
    const [id, dateadded, url, urlStatus, , threat, tags, urlhausLink, reporter] = fields;
    if (!id || !url) continue;
    const parsedDate = dateadded ? new Date(dateadded.replace(" ", "T")) : null;
    rows.push({
      urlhausId: id,
      url,
      urlStatus: urlStatus || null,
      threat: threat || null,
      tags: tags ? tags.split(",").map((t) => t.trim()).filter(Boolean) : [],
      urlhausLink: urlhausLink || null,
      reporter: reporter || null,
      dateAdded: parsedDate && !isNaN(parsedDate.getTime()) ? parsedDate : null,
    });
  }
  return rows;
}

/**
 * Downloads the feed and inserts any rows not already cached. Existing rows
 * are left as-is. organizationId picks whose abuse.ch Auth-Key to use; without
 * one (scheduled syncs) only the env-var keys are tried. Throws
 * AbuseChFeedError when there's no usable key or the download fails.
 */
export async function syncUrlhausFeed(organizationId?: string): Promise<{ total: number; added: number }> {
  const text = await fetchAbuseChExport("urlhaus", "recent.csv", organizationId);
  const rows = parseUrlhausCsv(text);
  if (rows.length === 0) return { total: 0, added: 0 };

  // ~100k+ rows per export: batched, since one `in` list or createMany that
  // size would exceed Postgres's 32,767 bind-parameter limit.
  const existingIds = new Set<string>();
  for (const ids of chunk(rows.map((r) => r.urlhausId), 10_000)) {
    const found = await prisma.urlhausFeedEntry.findMany({ where: { urlhausId: { in: ids } }, select: { urlhausId: true } });
    for (const r of found) existingIds.add(r.urlhausId);
  }
  const newRows = rows.filter((r) => !existingIds.has(r.urlhausId));

  for (const batch of chunk(newRows, 2_000)) {
    await prisma.urlhausFeedEntry.createMany({ data: batch, skipDuplicates: true });
  }

  return { total: rows.length, added: newRows.length };
}

/**
 * Checks already-persisted IocRecord rows against the local feed cache and,
 * for any hit, writes a real IocEnrichment (provider "urlhaus_feed") and
 * bumps IocRecord.reputation — a feed match is a confirmed detection, so it
 * never downgrades a higher score another provider already assigned.
 */
export async function matchUrlhausFeed(records: { id: string; value: string; type: string }[]): Promise<number> {
  const urlRecords = records.filter((r) => r.type === "url");
  if (urlRecords.length === 0) return 0;

  const distinctValues = Array.from(new Set(urlRecords.map((r) => r.value)));
  const hits = await prisma.urlhausFeedEntry.findMany({
    where: { url: { in: distinctValues } },
    select: { url: true, urlhausId: true, threat: true, tags: true, urlhausLink: true },
  });
  if (hits.length === 0) return 0;

  const hitByUrl = new Map(hits.map((h) => [h.url, h]));
  const now = new Date();
  const FEED_REPUTATION = 95;
  let matched = 0;

  for (const rec of urlRecords) {
    const hit = hitByUrl.get(rec.value);
    if (!hit) continue;
    matched++;

    const response = { urlhaus_id: hit.urlhausId, threat: hit.threat, tags: hit.tags, urlhaus_link: hit.urlhausLink };
    await prisma.iocEnrichment.upsert({
      where: { iocId_provider: { iocId: rec.id, provider: "urlhaus_feed" } },
      create: { iocId: rec.id, provider: "urlhaus_feed", status: "ok", response: response as never, enrichedAt: now },
      update: { status: "ok", response: response as never, enrichedAt: now, errorMsg: null },
    });

    const current = await prisma.iocRecord.findUnique({ where: { id: rec.id }, select: { reputation: true } });
    await prisma.iocRecord.update({
      where: { id: rec.id },
      data: {
        enrichedAt: now,
        ...(current && current.reputation !== null && current.reputation >= FEED_REPUTATION
          ? {}
          : { reputation: FEED_REPUTATION, threatType: hit.threat ?? undefined }),
      },
    });
  }

  return matched;
}
