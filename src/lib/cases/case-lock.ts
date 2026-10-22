/**
 * Closed-case freeze. Once a case is closed, its record — linked
 * investigations and analysis uploads, findings, notes, tasks, reports —
 * is the concluded record of the incident and must not change until the
 * case is explicitly reopened (with a reason, see /api/cases/[id] PATCH).
 *
 * Every route that mutates case-scoped data resolves the owning case
 * through guardCaseOpen() and returns its response when it's non-null.
 * The same guard freezes an archived investigation/upload that has no case
 * (see archive.ts).
 * Reading, exporting and generating reports stay allowed; so does IOC
 * enrichment, since it refreshes shared threat-intel records rather than
 * anything stored on the case.
 */
import { NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { formatCaseNumber } from "@/lib/cases/case-number";
import { legalHoldForCase } from "@/lib/cases/legal-hold";

export const CLOSED_STATUS = "closed";

export const CLOSURE_DISPOSITIONS = ["true_positive", "false_positive", "benign", "inconclusive"] as const;
export type ClosureDisposition = (typeof CLOSURE_DISPOSITIONS)[number];

export type CaseLockRef =
  | { caseId: string | null | undefined }
  | { investigationId: string | null | undefined }
  | { findingId: string }
  | { evidenceId: string }
  | { noteId: string }
  | { reportId: string }
  | { logUploadId: string }
  | { pcapUploadId: string }
  | { ramUploadId: string }
  | { windowsArtifactUploadId: string };

type CaseSummary = { id: string; caseSeq: number; title: string; status: string };
const CASE_SELECT = { id: true, caseSeq: true, title: true, status: true } as const;
// An investigation/upload with its own archive flag (only ever set when it
// belongs to no case — see archive.ts) and its case, if any.
const OWNER_SELECT = { archivedAt: true, case: { select: CASE_SELECT } } as const;

type Lock = { kase: CaseSummary | null; archivedItem: string | null };
const NONE: Lock = { kase: null, archivedItem: null };
const owner = (o: { archivedAt: Date | null; case: CaseSummary | null } | null | undefined, label: string): Lock =>
  o ? { kase: o.case, archivedItem: o.archivedAt ? label : null } : NONE;

async function resolveLock(ref: CaseLockRef): Promise<Lock> {
  if ("caseId" in ref) {
    return { kase: ref.caseId ? await prisma.case.findUnique({ where: { id: ref.caseId }, select: CASE_SELECT }) : null, archivedItem: null };
  }
  if ("investigationId" in ref) {
    if (!ref.investigationId) return NONE;
    return owner(await prisma.investigation.findUnique({ where: { id: ref.investigationId }, select: OWNER_SELECT }), "investigation");
  }
  if ("findingId" in ref) {
    const f = await prisma.finding.findUnique({ where: { id: ref.findingId }, select: { investigation: { select: OWNER_SELECT } } });
    return owner(f?.investigation, "investigation");
  }
  if ("evidenceId" in ref) {
    const e = await prisma.evidence.findUnique({ where: { id: ref.evidenceId }, select: { investigation: { select: OWNER_SELECT } } });
    return owner(e?.investigation, "investigation");
  }
  if ("noteId" in ref) {
    const n = await prisma.note.findUnique({ where: { id: ref.noteId }, select: { investigationId: true, findingId: true, evidenceId: true } });
    if (!n) return NONE;
    if (n.investigationId) return resolveLock({ investigationId: n.investigationId });
    if (n.findingId) return resolveLock({ findingId: n.findingId });
    return n.evidenceId ? resolveLock({ evidenceId: n.evidenceId }) : NONE;
  }
  if ("reportId" in ref) {
    const r = await prisma.report.findUnique({
      where: { id: ref.reportId },
      select: { case: { select: CASE_SELECT }, investigation: { select: OWNER_SELECT } },
    });
    if (!r) return NONE;
    return r.case ? { kase: r.case, archivedItem: null } : owner(r.investigation, "investigation");
  }
  if ("logUploadId" in ref) {
    return owner(await prisma.logUpload.findUnique({ where: { id: ref.logUploadId }, select: OWNER_SELECT }), "log upload");
  }
  if ("pcapUploadId" in ref) {
    return owner(await prisma.pcapUpload.findUnique({ where: { id: ref.pcapUploadId }, select: OWNER_SELECT }), "PCAP upload");
  }
  if ("ramUploadId" in ref) {
    return owner(await prisma.ramUpload.findUnique({ where: { id: ref.ramUploadId }, select: OWNER_SELECT }), "RAM upload");
  }
  return owner(await prisma.windowsArtifactUpload.findUnique({ where: { id: ref.windowsArtifactUploadId }, select: OWNER_SELECT }), "Windows artifact collection");
}

export function caseClosedResponse(kase: CaseSummary, action: string): NextResponse {
  return NextResponse.json(
    {
      error: `${formatCaseNumber(kase.caseSeq)} "${kase.title}" is closed — reopen it before ${action}.`,
      code: "case_closed",
      caseId: kase.id,
    },
    { status: 403 },
  );
}

export function itemArchivedResponse(label: string, action: string): NextResponse {
  return NextResponse.json(
    { error: `This ${label} is archived — restore it from the Archive page before ${action}.`, code: "archived" },
    { status: 403 },
  );
}

/**
 * Returns a 403 response when `ref` belongs to a closed case (an archived
 * case is always closed too) or is itself an archived item with no case;
 * otherwise null. `action` completes the sentence "… before …", e.g.
 * "adding notes".
 */
export async function guardCaseOpen(ref: CaseLockRef, action: string): Promise<NextResponse | null> {
  const { kase, archivedItem } = await resolveLock(ref);
  if (kase && kase.status === CLOSED_STATUS) return caseClosedResponse(kase, action);
  return archivedItem ? itemArchivedResponse(archivedItem, action) : null;
}

/**
 * guardCaseOpen() plus legal hold, for routes that destroy data (deleting a
 * case, an upload, a report or a note). A hold blocks deletion even while
 * the case is open; legal hold itself is an Enterprise feature (see
 * legal-hold.ts — Core's stub never reports one).
 */
export async function guardDeletion(ref: CaseLockRef, action: string): Promise<NextResponse | null> {
  const lock = await resolveLock(ref);
  if (lock.kase && lock.kase.status === CLOSED_STATUS) return caseClosedResponse(lock.kase, action);
  if (lock.archivedItem) return itemArchivedResponse(lock.archivedItem, action);
  const hold = lock.kase ? await legalHoldForCase(lock.kase.id) : null;
  if (lock.kase && hold) {
    return NextResponse.json(
      {
        error: `${formatCaseNumber(lock.kase.caseSeq)} "${lock.kase.title}" is under legal hold (${hold.reason}) — the hold must be released before ${action}.`,
        code: "legal_hold",
        caseId: lock.kase.id,
      },
      { status: 403 },
    );
  }
  return null;
}

/**
 * Work still running against a case. Closing while any of it is in flight
 * would let a worker write findings into a case that's already concluded.
 */
export async function pendingCaseWork(caseId: string) {
  const busy = { in: ["pending", "queued", "processing"] };
  const [logUploads, pcapUploads, ramUploads, ramSessions, windowsArtifactFiles, aiAnalyses] = await Promise.all([
    prisma.logUpload.count({ where: { caseId, status: busy } }),
    prisma.pcapUpload.count({ where: { caseId, status: busy } }),
    prisma.ramUpload.count({ where: { caseId, status: busy } }),
    prisma.ramUploadSession.count({ where: { caseId, status: "uploading" } }),
    prisma.windowsArtifactFile.count({ where: { upload: { caseId }, status: busy } }),
    // Only in-flight AI analyses block: queued ones are skipped by the AI
    // worker once the case is closed (see ai-worker.ts).
    prisma.finding.count({ where: { investigation: { caseId }, aiStatus: "processing" } }),
  ]);
  const counts = { logUploads, pcapUploads, ramUploads, ramSessions, windowsArtifactFiles, aiAnalyses };
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return { total, counts };
}
