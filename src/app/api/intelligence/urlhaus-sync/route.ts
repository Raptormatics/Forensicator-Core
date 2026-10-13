export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { syncUrlhausFeed } from "@/lib/intelligence/urlhaus-feed";

/** GET /api/intelligence/urlhaus-sync — when the local feed cache was last refreshed. */
export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const [latest, totalEntries] = await Promise.all([
    prisma.urlhausFeedEntry.findFirst({ orderBy: { syncedAt: "desc" }, select: { syncedAt: true } }),
    prisma.urlhausFeedEntry.count(),
  ]);

  return NextResponse.json({
    lastSyncedAt: latest?.syncedAt ?? null,
    totalEntries,
  });
}

/** POST /api/intelligence/urlhaus-sync — manual "Sync Now" for the local URLhaus feed cache. */
export async function POST(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  try {
    const result = await syncUrlhausFeed();
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json({ error: "sync_failed", message: err instanceof Error ? err.message : "Unknown error" }, { status: 502 });
  }
}
