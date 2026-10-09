export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { severityRank } from "@/lib/severity";

const VALID_STATUSES = new Set(["new", "under_review", "confirmed", "false_positive", "escalated", "resolved"]);

/**
 * GET /api/findings — cross-investigation findings triage list. Backs the
 * global /findings page, which the dashboard's KPI cards and "My Assigned
 * Findings" empty-state CTA both link into.
 */
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const { searchParams } = new URL(req.url);
  const statusParam = searchParams.get("status") ?? undefined;
  const statuses = statusParam ? statusParam.split(",").filter((s) => VALID_STATUSES.has(s)) : undefined;
  const assignee = searchParams.get("assignee") ?? undefined; // "me" | "unassigned" | undefined (all)
  const severityParam = searchParams.get("severity") ?? undefined;
  const severities = severityParam ? severityParam.split(",") : undefined;
  const caseId = searchParams.get("caseId") ?? undefined;
  const q = searchParams.get("q") ?? undefined;
  const page = Math.max(1, Number(searchParams.get("page") ?? 1));
  const limit = Math.min(100, Math.max(1, Number(searchParams.get("limit") ?? 50)));

  const scope = orgWhere(actor);
  const invScope = { ...(Object.keys(scope).length > 0 ? scope : {}), ...(caseId ? { caseId } : {}) };

  const where = {
    investigation: invScope,
    ...(statuses && statuses.length > 0 ? { workflowStatus: { in: statuses } } : {}),
    ...(assignee === "me" ? { assigneeId: actor.id } : assignee === "unassigned" ? { assigneeId: null } : {}),
    ...(severities && severities.length > 0 ? { severity: { in: severities } } : {}),
    ...(q ? {
      OR: [
        { findingType: { contains: q, mode: "insensitive" as const } },
        { category: { contains: q, mode: "insensitive" as const } },
      ],
    } : {}),
  };

  // `severity` is free-text (Important/Notable/...), so DB orderBy would sort
  // alphabetically — fetch a bounded candidate set by recency, rank+slice in JS.
  // Total is counted separately (DB-side) so pagination stays accurate even
  // when there are more matches than fit in the ranking window.
  const [total, candidates] = await Promise.all([
    prisma.finding.count({ where }),
    prisma.finding.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: 500,
      select: {
        id: true, findingType: true, category: true, severity: true, workflowStatus: true, createdAt: true,
        assignee: { select: { id: true, name: true, email: true } },
        investigation: {
          select: {
            id: true, title: true, hostname: true,
            case: { select: { id: true, title: true, caseSeq: true } },
          },
        },
      },
    }),
  ]);

  const sorted = candidates.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.createdAt.getTime() - a.createdAt.getTime());
  const findings = sorted.slice((page - 1) * limit, (page - 1) * limit + limit);

  return NextResponse.json({ findings, total, page, limit });
}
