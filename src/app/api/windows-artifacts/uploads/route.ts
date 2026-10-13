import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { prisma } from "@/lib/db/prisma";
import { requireAuth, orgWhere } from "@/lib/auth/api-guard";
import { getWinArtifactsDir } from "@/lib/settings/system";
import { getWinArtifactsQueue } from "@/lib/jobs/queues";
import type { WinArtifactFileRole } from "@/lib/windows-artifacts/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Combined across every file in one upload — individual registry hives,
// Amcache.hve, and (later phases) Prefetch/LNK files are all sub-100MB in
// practice; this just bounds one triage bundle, same reasoning as PCAP's
// own 500MB single-file cap.
const MAX_TOTAL_BYTES = 500 * 1024 * 1024;

// Form-field name -> artifact role, for the single-file-per-collection roles.
const SINGLE_FILE_FIELDS: { field: string; role: WinArtifactFileRole }[] = [
  { field: "system", role: "system_hive" },
  { field: "software", role: "software_hive" },
  { field: "security", role: "security_hive" },
  { field: "amcache", role: "amcache_hive" },
];

function isUploadedFile(v: FormDataEntryValue | null): v is File {
  return !!v && typeof v !== "string" && "arrayBuffer" in v;
}

// ── GET /api/windows-artifacts/uploads ──────────────────────────────────────
export async function GET(req: NextRequest) {
  try {
    const actor = await requireAuth(req);
    const where = orgWhere(actor);

    const uploads = await prisma.windowsArtifactUpload.findMany({
      where: { ...where },
      orderBy: { createdAt: "desc" },
      take: 100,
      select: {
        id: true, hostname: true, notes: true, findingCount: true,
        createdAt: true, updatedAt: true,
        uploadedBy: { select: { email: true, name: true } },
        case: { select: { id: true, title: true, caseSeq: true } },
        files: { select: { id: true, role: true, filename: true, status: true, findingCount: true } },
      },
    });

    return NextResponse.json({ uploads });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── POST /api/windows-artifacts/uploads ─────────────────────────────────────
// Accepts a multi-file bundle in one POST — a real triage collection from
// one host gathers SYSTEM/SOFTWARE/NTUSER.DAT(xN)/Amcache.hve together, so
// this is one upload action, not one-file-per-upload like RAM/PCAP today.
// Each file becomes its own WindowsArtifactFile, queued as its own job —
// one bad hive in the bundle doesn't block the rest.
export async function POST(req: NextRequest) {
  try {
    const actor = await requireAuth(req);
    const formData = await req.formData();

    const hostname = String(formData.get("hostname") ?? "").trim() || null;
    const notes = String(formData.get("notes") ?? "").trim() || null;
    const orgId = String(formData.get("organizationId") ?? "").trim() || null;
    const caseId = String(formData.get("caseId") ?? "").trim() || null;

    if (!caseId) {
      return NextResponse.json({ error: "missing_case", message: "Every artifact upload must be linked to a case. Select or create one before uploading." }, { status: 400 });
    }

    const kase = await prisma.case.findUnique({ where: { id: caseId }, select: { id: true, status: true } });
    if (!kase) {
      return NextResponse.json({ error: "invalid_case", message: "The specified case does not exist." }, { status: 400 });
    }
    if (kase.status === "closed") {
      return NextResponse.json({ error: "case_closed", message: "This case is closed and cannot accept new uploads. Reopen it first." }, { status: 403 });
    }

    type PendingFile = { role: WinArtifactFileRole; file: File; profileName: string | null };
    const pending: PendingFile[] = [];

    for (const { field, role } of SINGLE_FILE_FIELDS) {
      const f = formData.get(field);
      if (isUploadedFile(f)) pending.push({ role, file: f, profileName: null });
    }

    const ntuserFiles = formData.getAll("ntuser").filter(isUploadedFile);
    const ntuserNames = formData.getAll("ntuserProfileName").map((v) => String(v));
    ntuserFiles.forEach((file, i) => pending.push({ role: "ntuser_hive", file, profileName: ntuserNames[i]?.trim() || null }));

    const usrclassFiles = formData.getAll("usrclass").filter(isUploadedFile);
    const usrclassNames = formData.getAll("usrclassProfileName").map((v) => String(v));
    usrclassFiles.forEach((file, i) => pending.push({ role: "usrclass_hive", file, profileName: usrclassNames[i]?.trim() || null }));

    if (pending.length === 0) {
      return NextResponse.json({ error: "no_files", message: "Upload at least one artifact file (SYSTEM, SOFTWARE, NTUSER.DAT, or Amcache.hve)." }, { status: 400 });
    }

    const totalBytes = pending.reduce((sum, p) => sum + p.file.size, 0);
    if (totalBytes > MAX_TOTAL_BYTES) {
      return NextResponse.json({ error: "file_too_large", message: "Combined upload exceeds the 500 MB limit for one collection." }, { status: 413 });
    }

    const upload = await prisma.windowsArtifactUpload.create({
      data: {
        hostname, notes,
        uploadedById: actor.id,
        organizationId: orgId ?? (actor.organizationIds[0] ?? null),
        caseId,
      },
    });

    const dir = await getWinArtifactsDir();
    fs.mkdirSync(dir, { recursive: true });
    const queue = getWinArtifactsQueue();

    const createdFiles = [];
    for (const p of pending) {
      const buffer = Buffer.from(await p.file.arrayBuffer());
      const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");

      const fileRow = await prisma.windowsArtifactFile.create({
        data: {
          uploadId: upload.id,
          role: p.role,
          filename: p.file.name,
          fileSize: buffer.length,
          sha256,
          status: "queued",
          profileName: p.profileName,
        },
      });

      const ext = path.extname(p.file.name);
      const storagePath = path.join(dir, `${fileRow.id}${ext}`);
      fs.writeFileSync(storagePath, buffer);

      const job = await queue.add("process-winartifact-file", { winArtifactFileId: fileRow.id });
      const updated = await prisma.windowsArtifactFile.update({
        where: { id: fileRow.id },
        data: { storagePath, jobId: job.id ?? null },
      });
      createdFiles.push(updated);
    }

    return NextResponse.json({ upload: { ...upload, files: createdFiles } }, { status: 201 });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[windows-artifacts/uploads] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
