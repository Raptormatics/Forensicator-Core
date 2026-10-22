export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActor } from "@/lib/auth/actor";
import {
  CLOSED_STATUS, CLOSURE_DISPOSITIONS, caseClosedResponse, pendingCaseWork,
  type ClosureDisposition,
} from "@/lib/cases/case-lock";
import { legalHoldForCase } from "@/lib/cases/legal-hold";

type Params = { params: Promise<{ id: string }> };

const VALID_STATUSES = ["open", "active", "monitoring", "resolved", "closed"];
const MIN_REOPEN_REASON = 10;

// GET /api/cases/[id]
export async function GET(_req: NextRequest, props: Params) {
  const params = await props.params;
  const c = await prisma.case.findUnique({
    where: { id: params.id },
    include: {
      createdBy:  { select: { id: true, email: true, name: true } },
      assignee:   { select: { id: true, email: true, name: true } },
      notes:      { orderBy: { createdAt: "desc" }, include: { author: { select: { email: true, name: true } } } },
      investigations: {
        select: { id: true, title: true, hostname: true, status: true, findingCount: true },
      },
    },
  });
  if (!c) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const userIds = [c.closedById, c.reopenedById, c.archivedById].filter((v): v is string => !!v);
  const users = userIds.length
    ? await prisma.user.findMany({ where: { id: { in: userIds } }, select: { id: true, email: true, name: true } })
    : [];
  const byId = new Map(users.map((u) => [u.id, u]));
  const closureHistory = await prisma.auditLog.findMany({
    where: { resourceType: "case", resourceId: c.id, action: { in: ["case_closed", "case_reopened", "archived", "archive_restored"] } },
    orderBy: { createdAt: "desc" },
    select: { id: true, action: true, actorEmail: true, metadata: true, createdAt: true },
  });

  return NextResponse.json({
    case: {
      ...c,
      closedBy: c.closedById ? byId.get(c.closedById) ?? null : null,
      reopenedBy: c.reopenedById ? byId.get(c.reopenedById) ?? null : null,
      archivedBy: c.archivedById ? byId.get(c.archivedById) ?? null : null,
      closureHistory,
    },
  });
}

// PATCH /api/cases/[id]
//
// Closing (status -> "closed") requires { closureDisposition, closureSummary }
// and no upload still processing. Once closed, the only accepted change is a
// reopen: { status: <any non-closed status>, reopenReason }.
export async function PATCH(req: NextRequest, props: Params) {
  const params = await props.params;
  const actor = await getActor(req);
  const body = await req.json();
  const { title, description, status, severity, tags, assigneeId, incidentType } = body;

  const kase = await prisma.case.findUnique({
    where: { id: params.id },
    select: { id: true, caseSeq: true, title: true, status: true, organizationId: true, archivedAt: true },
  });
  if (!kase) return NextResponse.json({ error: "Case not found" }, { status: 404 });

  if (status !== undefined && !VALID_STATUSES.includes(status)) {
    return NextResponse.json({ error: "invalid_status" }, { status: 400 });
  }

  const audit = (action: string, metadata: Record<string, unknown>) =>
    prisma.auditLog.create({
      data: {
        actorId: actor.id, actorEmail: actor.email, actorIp: req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? null,
        action, resourceType: "case", resourceId: kase.id, organizationId: kase.organizationId, metadata: metadata as never,
      },
    });

  // ── Reopen ──────────────────────────────────────────────────────────────
  if (kase.status === CLOSED_STATUS) {
    const otherFields = [title, description, severity, tags, assigneeId, incidentType].some((v) => v !== undefined);
    if (status === undefined || status === CLOSED_STATUS || otherFields) {
      return caseClosedResponse(kase, "changing it");
    }
    if (kase.archivedAt) {
      return NextResponse.json(
        { error: "This case is archived — restore it from the Archive page before reopening it.", code: "archived" },
        { status: 403 },
      );
    }
    const reopenReason = typeof body.reopenReason === "string" ? body.reopenReason.trim() : "";
    if (reopenReason.length < MIN_REOPEN_REASON) {
      return NextResponse.json(
        { error: `Give a reason for reopening this case (at least ${MIN_REOPEN_REASON} characters).`, code: "reopen_reason_required" },
        { status: 400 },
      );
    }
    const c = await prisma.case.update({
      where: { id: kase.id },
      data: { status, reopenedAt: new Date(), reopenedById: actor.id, reopenReason },
    });
    await audit("case_reopened", { reason: reopenReason, status });
    return NextResponse.json({ case: c });
  }

  // ── Close ───────────────────────────────────────────────────────────────
  let closure = {};
  if (status === CLOSED_STATUS) {
    const closureDisposition = body.closureDisposition as ClosureDisposition;
    const closureSummary = typeof body.closureSummary === "string" ? body.closureSummary.trim() : "";
    if (!CLOSURE_DISPOSITIONS.includes(closureDisposition) || !closureSummary) {
      return NextResponse.json(
        { error: "Closing a case needs a disposition and a closure summary.", code: "closure_required" },
        { status: 400 },
      );
    }
    const pending = await pendingCaseWork(kase.id);
    if (pending.total > 0) {
      return NextResponse.json(
        {
          error: "This case still has uploads or analyses processing — wait for them to finish before closing it.",
          code: "case_work_pending",
          pending: pending.counts,
        },
        { status: 409 },
      );
    }
    closure = { closedAt: new Date(), closedById: actor.id, closureDisposition, closureSummary };
  }

  const c = await prisma.case.update({
    where: { id: kase.id },
    data: {
      ...(title       !== undefined ? { title }       : {}),
      ...(description !== undefined ? { description } : {}),
      ...(status      !== undefined ? { status }      : {}),
      ...(severity    !== undefined ? { severity }    : {}),
      ...(tags        !== undefined ? { tags }        : {}),
      ...(assigneeId  !== undefined ? { assigneeId }  : {}),
      ...(incidentType !== undefined ? { incidentType: incidentType || null } : {}),
      ...closure,
    },
  });
  if (status === CLOSED_STATUS) {
    await audit("case_closed", { disposition: c.closureDisposition, summary: c.closureSummary });
  }
  return NextResponse.json({ case: c });
}

// DELETE /api/cases/[id] — a closed case is the concluded record of an
// incident and can't be deleted (reopen it first). Deleting an open case
// unlinks its investigations and uploads; they're kept, not deleted.
export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  const actor = await getActor(req);
  const kase = await prisma.case.findUnique({
    where: { id: params.id },
    select: { id: true, caseSeq: true, title: true, status: true, organizationId: true },
  });
  if (!kase) return NextResponse.json({ error: "Case not found" }, { status: 404 });
  if (kase.status === CLOSED_STATUS) return caseClosedResponse(kase, "deleting it");
  const hold = await legalHoldForCase(kase.id);
  if (hold) {
    return NextResponse.json(
      { error: `This case is under legal hold (${hold.reason}) — the hold must be released before deleting it.`, code: "legal_hold" },
      { status: 403 },
    );
  }

  await prisma.case.delete({ where: { id: kase.id } });
  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email, action: "delete", resourceType: "case", resourceId: kase.id,
      organizationId: kase.organizationId, severity: "warning", metadata: { caseSeq: kase.caseSeq, title: kase.title } as never,
    },
  });
  return NextResponse.json({ ok: true });
}
