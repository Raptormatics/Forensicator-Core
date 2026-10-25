/**
 * Organization access checks for single records. Lists are filtered with orgWhere();
 * a route that loads one record by id resolves the organization owning it
 * here and refuses it if the actor can't access that organization
 * (orgAccessScope() in api-guard.ts).
 *
 * Refusals are 404, not 403, so another organization's record is
 * indistinguishable from one that doesn't exist. Core is single-org, so
 * orgAccessScope() is unrestricted and these checks cost nothing there.
 */
import { NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import type { NextRequest } from "next/server";
import { orgAccessScope, orgWhere, getActorOrThrow, AuthError, type AuthActor } from "@/lib/auth/api-guard";

export type OrgRef =
  | { organizationId: string | null }
  | { caseId: string }
  | { investigationId: string }
  | { findingId: string }
  | { evidenceId: string }
  | { noteId: string }
  | { reportId: string }
  | { logUploadId: string }
  | { pcapUploadId: string }
  | { ramUploadId: string }
  | { ramSessionId: string }
  | { ramMalfindRegionId: string }
  | { ramSymbolTableId: string }
  | { windowsArtifactUploadId: string }
  | { quarantinePayloadId: string };

const ORG = { organizationId: true } as const;

/** The owning organization (null for records with none), or undefined when the record doesn't exist. */
export async function resolveOwnerOrg(ref: OrgRef): Promise<string | null | undefined> {
  if ("organizationId" in ref) return ref.organizationId;
  if ("caseId" in ref) return (await prisma.case.findUnique({ where: { id: ref.caseId }, select: ORG }))?.organizationId;
  if ("investigationId" in ref) return (await prisma.investigation.findUnique({ where: { id: ref.investigationId }, select: ORG }))?.organizationId;
  if ("findingId" in ref) {
    const f = await prisma.finding.findUnique({ where: { id: ref.findingId }, select: { investigation: { select: ORG } } });
    return f ? f.investigation.organizationId : undefined;
  }
  if ("evidenceId" in ref) {
    const e = await prisma.evidence.findUnique({ where: { id: ref.evidenceId }, select: { investigation: { select: ORG } } });
    return e ? e.investigation.organizationId : undefined;
  }
  if ("noteId" in ref) {
    const n = await prisma.note.findUnique({
      where: { id: ref.noteId },
      select: { investigation: { select: ORG }, finding: { select: { investigation: { select: ORG } } }, evidenceId: true },
    });
    if (!n) return undefined;
    if (n.investigation) return n.investigation.organizationId;
    if (n.finding) return n.finding.investigation.organizationId;
    return n.evidenceId ? resolveOwnerOrg({ evidenceId: n.evidenceId }) : null;
  }
  if ("reportId" in ref) {
    const r = await prisma.report.findUnique({ where: { id: ref.reportId }, select: { case: { select: ORG }, investigation: { select: ORG } } });
    if (!r) return undefined;
    return r.case?.organizationId ?? r.investigation?.organizationId ?? null;
  }
  if ("logUploadId" in ref) return (await prisma.logUpload.findUnique({ where: { id: ref.logUploadId }, select: ORG }))?.organizationId;
  if ("pcapUploadId" in ref) return (await prisma.pcapUpload.findUnique({ where: { id: ref.pcapUploadId }, select: ORG }))?.organizationId;
  if ("ramUploadId" in ref) return (await prisma.ramUpload.findUnique({ where: { id: ref.ramUploadId }, select: ORG }))?.organizationId;
  if ("ramSessionId" in ref) return (await prisma.ramUploadSession.findUnique({ where: { id: ref.ramSessionId }, select: ORG }))?.organizationId;
  if ("ramSymbolTableId" in ref) return (await prisma.ramSymbolTable.findUnique({ where: { id: ref.ramSymbolTableId }, select: ORG }))?.organizationId;
  if ("ramMalfindRegionId" in ref) {
    const r = await prisma.ramMalfindRegion.findUnique({ where: { id: ref.ramMalfindRegionId }, select: { finding: { select: { upload: { select: ORG } } } } });
    return r ? r.finding.upload.organizationId : undefined;
  }
  if ("windowsArtifactUploadId" in ref) return (await prisma.windowsArtifactUpload.findUnique({ where: { id: ref.windowsArtifactUploadId }, select: ORG }))?.organizationId;
  const q = await prisma.defenderQuarantinePayload.findUnique({ where: { id: ref.quarantinePayloadId }, select: { file: { select: { upload: { select: ORG } } } } });
  return q ? q.file.upload.organizationId : undefined;
}

/** Whether the actor may access records owned by `organizationId` (null = no organization). */
export function canAccessOrg(actor: AuthActor, organizationId: string | null): boolean {
  const scope = orgAccessScope(actor);
  if (scope === null) return true;
  return organizationId !== null && scope.includes(organizationId);
}

const notFound = () => NextResponse.json({ error: "Not found" }, { status: 404 });

/**
 * Returns a 404 response when the record doesn't exist or belongs to an
 * organization the actor can't access; otherwise null. Unrestricted actors
 * (always, in Core) skip the lookup entirely.
 */
export async function guardOrgAccess(actor: AuthActor, ref: OrgRef): Promise<NextResponse | null> {
  if (orgAccessScope(actor) === null) return null;
  const org = await resolveOwnerOrg(ref);
  if (org === undefined) return notFound();
  return canAccessOrg(actor, org) ? null : notFound();
}

/** 403 unless the actor administers the instance (see isInstanceAdminActor in api-guard.ts). */
export function instanceAdminRequired(): NextResponse {
  return NextResponse.json({ error: "Only an instance administrator can do this." }, { status: 403 });
}

/**
 * The authenticated caller, or the 401 response to return. Every route
 * must resolve its caller itself: middleware only checks that a session
 * cookie or an Authorization: Bearer header is *present*, not that the
 * API key behind it is valid.
 */
export async function actorOr401(req: NextRequest): Promise<AuthActor | NextResponse> {
  try {
    return await getActorOrThrow(req);
  } catch (e) {
    if (e instanceof AuthError) return e.toResponse();
    throw e;
  }
}

/** `where` fragment for rows reached through their investigation (Finding, Evidence, ActivityLog, ...). */
export function investigationOrgWhere(actor: AuthActor) {
  const w = orgWhere(actor);
  return Object.keys(w).length ? { investigation: w } : {};
}
