/**
 * Archive — the step after closing. A closed case is archived as a whole;
 * an investigation or analysis upload is archived on its own only when it
 * belongs to no case (one inside a case is archived through that case,
 * never individually, so a case's record can't be fragmented). Archived
 * data is hidden from the working lists, dashboard and search but kept
 * intact: host profiles still count it, direct links still open it, and
 * it's frozen by the same guard as a closed case (case-lock.ts).
 *
 * Restoring is the reverse and is two-step for a case: archived -> closed
 * (here), then closed -> reopened with a reason (/api/cases/[id] PATCH).
 */
import { prisma } from "@/lib/db/prisma";
import { formatCaseNumber } from "@/lib/cases/case-number";
import { CLOSED_STATUS } from "@/lib/cases/case-lock";
import type { AuthActor } from "@/lib/auth/api-guard";

export const ARCHIVE_TYPES = ["case", "investigation", "log", "pcap", "ram", "windows-artifacts"] as const;
export type ArchiveType = (typeof ARCHIVE_TYPES)[number];

const ITEM_LABEL: Record<ArchiveType, string> = {
  case: "case",
  investigation: "investigation",
  log: "log upload",
  pcap: "PCAP upload",
  ram: "RAM upload",
  "windows-artifacts": "Host artifact collection",
};

/**
 * `where` fragment excluding archived investigations/uploads: archived
 * themselves, or in an archived case. Combine with a caller's own filter
 * via `{ AND: [where, notArchived()] }` so neither side's OR is clobbered.
 */
export function notArchived() {
  return { archivedAt: null, OR: [{ caseId: null }, { case: { archivedAt: null } }] };
}

/** Same fragment, for rows reached through their investigation (Finding). */
export function investigationNotArchived() {
  return { investigation: notArchived() };
}

/** True when an investigation/upload counts as archived. */
export function isArchived(item: { archivedAt: Date | null; case?: { archivedAt: Date | null } | null }): boolean {
  return !!item.archivedAt || !!item.case?.archivedAt;
}

export class ArchiveError extends Error {
  constructor(message: string, public status = 409) { super(message); }
}

const BUSY = ["pending", "queued", "processing"];

type ItemRow = { id: string; caseId: string | null; archivedAt: Date | null; organizationId: string | null; busy: boolean };

async function loadItem(type: Exclude<ArchiveType, "case">, id: string): Promise<ItemRow | null> {
  const base = { id: true, caseId: true, archivedAt: true, organizationId: true } as const;
  switch (type) {
    case "investigation": {
      const r = await prisma.investigation.findUnique({ where: { id }, select: base });
      return r && { ...r, busy: false };
    }
    case "log": {
      const r = await prisma.logUpload.findUnique({ where: { id }, select: { ...base, status: true } });
      return r && { ...r, busy: BUSY.includes(r.status) };
    }
    case "pcap": {
      const r = await prisma.pcapUpload.findUnique({ where: { id }, select: { ...base, status: true } });
      return r && { ...r, busy: BUSY.includes(r.status) };
    }
    case "ram": {
      const r = await prisma.ramUpload.findUnique({ where: { id }, select: { ...base, status: true } });
      return r && { ...r, busy: BUSY.includes(r.status) };
    }
    case "windows-artifacts": {
      const r = await prisma.windowsArtifactUpload.findUnique({
        where: { id },
        select: { ...base, _count: { select: { files: { where: { status: { in: BUSY } } } } } },
      });
      return r && { id: r.id, caseId: r.caseId, archivedAt: r.archivedAt, organizationId: r.organizationId, busy: r._count.files > 0 };
    }
  }
}

async function setItemArchive(type: Exclude<ArchiveType, "case">, id: string, data: { archivedAt: Date | null; archivedById: string | null }) {
  switch (type) {
    case "investigation": return prisma.investigation.update({ where: { id }, data });
    case "log": return prisma.logUpload.update({ where: { id }, data });
    case "pcap": return prisma.pcapUpload.update({ where: { id }, data });
    case "ram": return prisma.ramUpload.update({ where: { id }, data });
    case "windows-artifacts": return prisma.windowsArtifactUpload.update({ where: { id }, data });
  }
}

/** Archive or restore one item. Throws ArchiveError with a user-facing message when it isn't allowed. */
export async function setArchived(
  type: ArchiveType, id: string, archive: boolean, actor: AuthActor, actorIp: string | null,
): Promise<void> {
  const label = ITEM_LABEL[type];
  let organizationId: string | null;

  if (type === "case") {
    const kase = await prisma.case.findUnique({ where: { id }, select: { caseSeq: true, status: true, archivedAt: true, organizationId: true } });
    if (!kase) throw new ArchiveError("Case not found.", 404);
    const ref = formatCaseNumber(kase.caseSeq);
    if (archive && kase.status !== CLOSED_STATUS) throw new ArchiveError(`${ref} is still open — close it before archiving it.`);
    if (archive && kase.archivedAt) throw new ArchiveError(`${ref} is already archived.`);
    if (!archive && !kase.archivedAt) throw new ArchiveError(`${ref} isn't archived.`);
    await prisma.case.update({ where: { id }, data: archive ? { archivedAt: new Date(), archivedById: actor.id } : { archivedAt: null, archivedById: null } });
    organizationId = kase.organizationId;
  } else {
    const item = await loadItem(type, id);
    if (!item) throw new ArchiveError(`${label[0].toUpperCase()}${label.slice(1)} not found.`, 404);
    if (archive && item.caseId) {
      throw new ArchiveError(`This ${label} belongs to a case — close and archive the case instead, so the case's record stays together.`);
    }
    if (archive && item.busy) throw new ArchiveError(`This ${label} is still processing — wait for it to finish before archiving it.`);
    if (archive && item.archivedAt) throw new ArchiveError(`This ${label} is already archived.`);
    if (!archive && !item.archivedAt) throw new ArchiveError(`This ${label} isn't archived on its own — if its case is archived, restore the case.`);
    await setItemArchive(type, id, archive ? { archivedAt: new Date(), archivedById: actor.id } : { archivedAt: null, archivedById: null });
    organizationId = item.organizationId;
  }

  await prisma.auditLog.create({
    data: {
      actorId: actor.id, actorEmail: actor.email, actorIp,
      action: archive ? "archived" : "archive_restored",
      resourceType: type === "case" ? "case" : type === "investigation" ? "investigation" : `${type}_upload`,
      resourceId: id, organizationId, metadata: { type } as never,
    },
  });
}
