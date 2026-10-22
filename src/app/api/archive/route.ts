export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { ARCHIVE_TYPES, ArchiveError, setArchived, type ArchiveType } from "@/lib/cases/archive";

const USER = { select: { id: true, email: true, name: true } } as const;

// GET /api/archive — everything archived: closed cases archived as a whole
// (with what they contain), and investigations/uploads archived on their
// own because they belong to no case.
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }
  const org = orgWhere(actor);
  const own = { ...org, caseId: null, archivedAt: { not: null } };
  const itemSelect = { id: true, archivedAt: true, archivedById: true, createdAt: true } as const;

  const [cases, investigations, logUploads, pcapUploads, ramUploads, windowsArtifactUploads] = await Promise.all([
    prisma.case.findMany({
      where: { ...org, archivedAt: { not: null } },
      orderBy: { archivedAt: "desc" },
      select: {
        id: true, caseSeq: true, title: true, severity: true, closureDisposition: true, closedAt: true,
        archivedAt: true, archivedById: true, assignee: USER,
        _count: { select: { investigations: true, logUploads: true, pcapUploads: true, ramUploads: true, windowsArtifactUploads: true } },
      },
    }),
    prisma.investigation.findMany({ where: own, orderBy: { archivedAt: "desc" }, select: { ...itemSelect, title: true, hostname: true, findingCount: true } }),
    prisma.logUpload.findMany({ where: own, orderBy: { archivedAt: "desc" }, select: { ...itemSelect, filename: true, hostname: true, findingCount: true } }),
    prisma.pcapUpload.findMany({ where: own, orderBy: { archivedAt: "desc" }, select: { ...itemSelect, filename: true, findingCount: true } }),
    prisma.ramUpload.findMany({ where: own, orderBy: { archivedAt: "desc" }, select: { ...itemSelect, filename: true, hostname: true, findingCount: true } }),
    prisma.windowsArtifactUpload.findMany({ where: own, orderBy: { archivedAt: "desc" }, select: { ...itemSelect, hostname: true, findingCount: true } }),
  ]);

  const userIds = [...new Set([cases, investigations, logUploads, pcapUploads, ramUploads, windowsArtifactUploads]
    .flat().map((r) => r.archivedById).filter((v): v is string => !!v))];
  const users = userIds.length ? await prisma.user.findMany({ where: { id: { in: userIds } }, select: { id: true, email: true, name: true } }) : [];
  const byId = Object.fromEntries(users.map((u) => [u.id, u]));
  const withUser = <T extends { archivedById: string | null }>(rows: T[]) =>
    rows.map((r) => ({ ...r, archivedBy: r.archivedById ? byId[r.archivedById] ?? null : null }));

  return NextResponse.json({
    cases: withUser(cases),
    investigations: withUser(investigations),
    uploads: {
      log: withUser(logUploads),
      pcap: withUser(pcapUploads),
      ram: withUser(ramUploads),
      "windows-artifacts": withUser(windowsArtifactUploads),
    },
  });
}

// POST /api/archive — { type, id, action: "archive" | "restore" }
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const body = await req.json().catch(() => ({}));
  const type = body.type as ArchiveType;
  const action = body.action;
  if (!ARCHIVE_TYPES.includes(type) || typeof body.id !== "string" || (action !== "archive" && action !== "restore")) {
    return NextResponse.json({ error: "type, id and action (archive | restore) are required" }, { status: 400 });
  }
  try {
    await setArchived(type, body.id, action === "archive", actor, req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? null);
  } catch (e) {
    if (e instanceof ArchiveError) return NextResponse.json({ error: e.message, code: "archive_refused" }, { status: e.status });
    throw e;
  }
  return NextResponse.json({ ok: true });
}
