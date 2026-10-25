import { NextRequest, NextResponse } from "next/server";
import { Readable } from "stream";
import type { ReadableStream as NodeWebReadableStream } from "stream/web";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import busboy from "busboy";
import { prisma } from "@/lib/db/prisma";
import { requireAuth, orgWhere } from "@/lib/auth/api-guard";
import { getRamDir } from "@/lib/settings/system";
import { getRamQueue } from "@/lib/jobs/queues";
import { ALLOWED_EXTENSIONS_BY_OS, ALLOWED_OS_TYPES, getMaxBytes, matchedExtension } from "@/lib/ram-analysis/upload-shared";
import { notArchived } from "@/lib/cases/archive";
import { canAccessOrg } from "@/lib/auth/org-access";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// ── GET /api/ram-analysis/uploads ──────────────────────────────────────────
export async function GET(req: NextRequest) {
  try {
    const actor = await requireAuth(req);
    const where = orgWhere(actor);

    // Archived uploads (or ones in an archived case) are on the Archive page.
    const uploads = await prisma.ramUpload.findMany({
      where: { ...where, ...notArchived() },
      orderBy: { createdAt: "desc" },
      take: 100,
      select: {
        id: true, filename: true, fileSize: true, status: true,
        processCount: true, connectionCount: true, findingCount: true, iocCount: true,
        osType: true, osBuild: true, osArch: true,
        hostname: true, assetName: true, ipAddress: true, errorMessage: true,
        createdAt: true, updatedAt: true,
        uploadedBy: { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
        case: { select: { id: true, title: true, caseSeq: true, status: true, archivedAt: true } },
        _count: { select: { processes: true, connections: true, findings: true, iocs: true } },
      },
    });

    return NextResponse.json({
      uploads: uploads.map((u) => ({ ...u, fileSize: u.fileSize.toString() })),
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── Streaming multipart parse ───────────────────────────────────────────────
// Bypasses req.formData() deliberately — Next.js 14's formData() (undici)
// already fully materializes multipart file parts in memory while parsing,
// which is fine for the 500MB PCAP cap but would risk OOM-killing the
// process for a memory dump that can be tens of GB. Streams the file part
// straight to disk while incrementally hashing, never holding the whole
// file in memory at once.

type ParseResult =
  | { ok: true; fields: Record<string, string>; filename: string; storagePath: string; byteCount: number; sha256: string }
  | { ok: false; error: "invalid_os_type" | "invalid_file_type" | "missing_case" | "missing_file" | "file_too_large" | "parse_error"; message: string; storagePath?: string };

function parseRamUpload(
  body: NodeWebReadableStream<Uint8Array>,
  contentType: string,
  opts: { ramDir: string; uploadId: string; maxBytes: number }
): Promise<ParseResult> {
  return new Promise((resolve) => {
    const fields: Record<string, string> = {};
    let settled = false;
    let byteCount = 0;
    let storagePath: string | undefined;
    let filename: string | undefined;
    let hash: crypto.Hash | undefined;
    let writeStream: fs.WriteStream | undefined;
    let fileSeen = false;
    let pendingWriteFinish: Promise<void> | null = null;

    const settle = (result: ParseResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const cleanupPartial = () => {
      writeStream?.destroy();
      if (storagePath) fs.unlink(storagePath, () => {});
    };

    const bb = busboy({ headers: { "content-type": contentType }, limits: { fileSize: opts.maxBytes } });

    bb.on("field", (name, value) => { fields[name] = value; });

    bb.on("file", (name, stream, info) => {
      if (name !== "file" || fileSeen) { stream.resume(); return; }
      fileSeen = true;

      const osType = fields.osType;
      if (!osType || !ALLOWED_OS_TYPES.includes(osType)) {
        stream.resume();
        settle({ ok: false, error: "invalid_os_type", message: "Select an operating system before uploading (osType must be sent before the file field)." });
        return;
      }
      const ext = matchedExtension(info.filename, osType);
      if (!ext) {
        stream.resume();
        settle({ ok: false, error: "invalid_file_type", message: `Only ${ALLOWED_EXTENSIONS_BY_OS[osType].join(", ")} files are supported for ${osType}.` });
        return;
      }
      if (!fields.caseId) {
        stream.resume();
        settle({ ok: false, error: "missing_case", message: "Every RAM upload must be linked to a case. Select or create one before uploading." });
        return;
      }

      filename = info.filename;
      storagePath = path.join(opts.ramDir, `${opts.uploadId}${ext}`);
      hash = crypto.createHash("sha256");
      writeStream = fs.createWriteStream(storagePath);

      stream.on("data", (chunk: Buffer) => {
        byteCount += chunk.length;
        hash!.update(chunk);
      });
      stream.on("limit", () => {
        cleanupPartial();
        settle({
          ok: false, error: "file_too_large",
          message: `Maximum RAM image size is ${(opts.maxBytes / (1024 ** 3)).toFixed(0)} GB.`,
        });
      });

      pendingWriteFinish = new Promise((res) => {
        writeStream!.on("finish", res);
        writeStream!.on("error", () => res());
      });
      stream.pipe(writeStream);
    });

    bb.on("error", () => {
      cleanupPartial();
      settle({ ok: false, error: "parse_error", message: "Failed to parse the upload." });
    });

    bb.on("close", async () => {
      if (settled) return;
      if (pendingWriteFinish) await pendingWriteFinish;
      if (!fileSeen || !storagePath || !filename || !hash) {
        settle({ ok: false, error: "missing_file", message: "Provide a file in the 'file' field." });
        return;
      }
      settle({ ok: true, fields, filename, storagePath, byteCount, sha256: hash.digest("hex") });
    });

    Readable.fromWeb(body).pipe(bb);
  });
}

// ── POST /api/ram-analysis/uploads ─────────────────────────────────────────
export async function POST(req: NextRequest) {
  try {
    const actor = await requireAuth(req);

    const maxBytes = getMaxBytes();
    const contentLengthHeader = req.headers.get("content-length");
    if (contentLengthHeader && Number(contentLengthHeader) > maxBytes) {
      return NextResponse.json(
        { error: "file_too_large", message: `Maximum RAM image size is ${(maxBytes / (1024 ** 3)).toFixed(0)} GB.` },
        { status: 413 }
      );
    }
    if (!req.body) {
      return NextResponse.json({ error: "missing_file", message: "Provide a file in the 'file' field." }, { status: 400 });
    }

    const ramDir = await getRamDir();
    fs.mkdirSync(ramDir, { recursive: true });
    const uploadId = crypto.randomUUID();

    const contentType = req.headers.get("content-type") ?? "";
    const result = await parseRamUpload(req.body as unknown as NodeWebReadableStream<Uint8Array>, contentType, { ramDir, uploadId, maxBytes });

    if (!result.ok) {
      const status = result.error === "file_too_large" ? 413 : 400;
      return NextResponse.json({ error: result.error, message: result.message }, { status });
    }

    const caseId = result.fields.caseId;
    const kase = await prisma.case.findUnique({ where: { id: caseId }, select: { id: true, status: true, organizationId: true } });
    // Another organization's case is treated as nonexistent.
    if (!kase || !canAccessOrg(actor, kase.organizationId)) {
      fs.unlink(result.storagePath, () => {});
      return NextResponse.json({ error: "invalid_case", message: "The specified case does not exist." }, { status: 400 });
    }
    if (kase.status === "closed") {
      fs.unlink(result.storagePath, () => {});
      return NextResponse.json({ error: "case_closed", message: "This case is closed and cannot accept new uploads. Reopen it first." }, { status: 403 });
    }

    const upload = await prisma.ramUpload.create({
      data: {
        id: uploadId,
        filename: result.filename,
        fileSize: BigInt(result.byteCount),
        sha256: result.sha256,
        status: "queued",
        storagePath: result.storagePath,
        osType: result.fields.osType,
        hostname: result.fields.hostname || null,
        assetName: result.fields.assetName || null,
        ipAddress: result.fields.ipAddress || null,
        notes: result.fields.notes || null,
        uploadedById: actor.id,
        organizationId: kase.organizationId,
        caseId,
      },
    });

    const job = await getRamQueue().add("process-ram", { ramUploadId: upload.id });

    const updated = await prisma.ramUpload.update({
      where: { id: upload.id },
      data: { jobId: job.id ?? null },
    });

    return NextResponse.json({ upload: { ...updated, fileSize: updated.fileSize.toString() } }, { status: 201 });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[ram-analysis/upload] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
