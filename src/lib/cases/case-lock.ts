/**
 * Closed-case freeze. Once a case is closed, its record — linked
 * investigations and analysis uploads, findings, notes, tasks, reports —
 * is the concluded record of the incident and must not change until the
 * case is explicitly reopened (with a reason, see /api/cases/[id] PATCH).
 *
 * Every route that mutates case-scoped data resolves the owning case
 * through guardCaseOpen() and returns its response when it's non-null.
 * Reading, exporting and generating reports stay allowed; so does IOC
 * enrichment, since it refreshes shared threat-intel records rather than
 * anything stored on the case.
 */
import { NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { formatCaseNumber } from "@/lib/cases/case-number";

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

async function resolveCase(ref: CaseLockRef): Promise<CaseSummary | null> {
  if ("caseId" in ref) {
    return ref.caseId ? prisma.case.findUnique({ where: { id: ref.caseId }, select: CASE_SELECT }) : null;
  }
  if ("investigationId" in ref) {
    if (!ref.investigationId) return null;
    const inv = await prisma.investigation.findUnique({ where: { id: ref.investigationId }, select: { case: { select: CASE_SELECT } } });
    return inv?.case ?? null;
  }
  if ("findingId" in ref) {
    const f = await prisma.finding.findUnique({ where: { id: ref.findingId }, select: { investigation: { select: { case: { select: CASE_SELECT } } } } });
    return f?.investigation.case ?? null;
  }
  if ("evidenceId" in ref) {
    const e = await prisma.evidence.findUnique({ where: { id: ref.evidenceId }, select: { investigation: { select: { case: { select: CASE_SELECT } } } } });
    return e?.investigation.case ?? null;
  }
  if ("noteId" in ref) {
    const n = await prisma.note.findUnique({ where: { id: ref.noteId }, select: { investigationId: true, findingId: true, evidenceId: true } });
    if (!n) return null;
    if (n.investigationId) return resolveCase({ investigationId: n.investigationId });
    if (n.findingId) return resolveCase({ findingId: n.findingId });
    return n.evidenceId ? resolveCase({ evidenceId: n.evidenceId }) : null;
  }
  if ("reportId" in ref) {
    const r = await prisma.report.findUnique({
      where: { id: ref.reportId },
      select: { case: { select: CASE_SELECT }, investigation: { select: { case: { select: CASE_SELECT } } } },
    });
    return r?.case ?? r?.investigation?.case ?? null;
  }
  if ("logUploadId" in ref) {
    return (await prisma.logUpload.findUnique({ where: { id: ref.logUploadId }, select: { case: { select: CASE_SELECT } } }))?.case ?? null;
  }
  if ("pcapUploadId" in ref) {
    return (await prisma.pcapUpload.findUnique({ where: { id: ref.pcapUploadId }, select: { case: { select: CASE_SELECT } } }))?.case ?? null;
  }
  if ("ramUploadId" in ref) {
    return (await prisma.ramUpload.findUnique({ where: { id: ref.ramUploadId }, select: { case: { select: CASE_SELECT } } }))?.case ?? null;
  }
  return (await prisma.windowsArtifactUpload.findUnique({ where: { id: ref.windowsArtifactUploadId }, select: { case: { select: CASE_SELECT } } }))?.case ?? null;
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

/**
 * Returns a 403 response when `ref` belongs to a closed case, otherwise null.
 * `action` completes the sentence "reopen it before …", e.g. "adding notes".
 */
export async function guardCaseOpen(ref: CaseLockRef, action: string): Promise<NextResponse | null> {
  const kase = await resolveCase(ref);
  return kase && kase.status === CLOSED_STATUS ? caseClosedResponse(kase, action) : null;
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
