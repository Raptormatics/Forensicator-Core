export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import type { Prisma } from "@prisma/client";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";

/**
 * GET /api/sigma/rules — Core's Sigma rule library.
 * ?q= (title, tags, id), ?level=, ?state=active|disabled|unsupported|no_source,
 * ?product=, ?limit=, ?offset=
 */
export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const sp = new URL(req.url).searchParams;
  const q = (sp.get("q") ?? "").trim();
  const level = sp.get("level") ?? "";
  const state = sp.get("state") ?? "";
  const product = sp.get("product") ?? "";
  const limit = Math.min(Number(sp.get("limit") ?? 100) || 100, 500);
  const offset = Math.max(Number(sp.get("offset") ?? 0) || 0, 0);

  const where: Prisma.SigmaRuleWhereInput = {
    ...(level ? { level } : {}),
    ...(product ? { product } : {}),
    ...(state === "active" ? { enabled: true, supported: true, covered: true }
      : state === "disabled" ? { enabled: false }
      : state === "unsupported" ? { supported: false }
      : state === "no_source" ? { supported: true, covered: false }
      : {}),
    ...(q ? { OR: [
      { title: { contains: q, mode: "insensitive" } },
      { sigmaId: { contains: q, mode: "insensitive" } },
      { tags: { has: q.toLowerCase() } },
      { description: { contains: q, mode: "insensitive" } },
    ] } : {}),
  };
  const [rules, total, products] = await Promise.all([
    prisma.sigmaRule.findMany({
      where,
      select: { id: true, sigmaId: true, title: true, level: true, status: true, product: true, category: true, service: true,
        tags: true, enabled: true, supported: true, covered: true, unsupportedReason: true, hitCount: true },
      orderBy: [{ hitCount: "desc" }, { title: "asc" }],
      take: limit, skip: offset,
    }),
    prisma.sigmaRule.count({ where }),
    prisma.sigmaRule.groupBy({ by: ["product"], _count: { _all: true } }),
  ]);
  return NextResponse.json({
    rules, total,
    products: products.filter((p) => p.product).map((p) => ({ product: p.product, count: p._count._all })).sort((a, b) => b.count - a.count),
  });
}
