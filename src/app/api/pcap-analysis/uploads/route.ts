import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { prisma } from "@/lib/db/prisma";
import { requireAuth, orgWhere } from "@/lib/auth/api-guard";
import { getPcapDir } from "@/lib/settings/system";
import { getPcapQueue } from "@/lib/jobs/queues";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const MAX_BYTES = 500 * 1024 * 1024; // 500 MB — raw captures are legitimately big
const ALLOWED_EXTENSIONS = [".pcap", ".pcapng"];

// ── GET /api/pcap-analysis/uploads ─────────────────────────────────────────
export async function GET(req: NextRequest) {
  try {
    const actor = await requireAuth(req);
    const where = orgWhere(actor);

    const uploads = await prisma.pcapUpload.findMany({
      where: { ...where },
      orderBy: { createdAt: "desc" },
      take: 100,
      select: {
        id: true, filename: true, status: true, packetCount: true, byteCount: true,
        conversationCount: true, dnsQueryCount: true, findingCount: true, iocCount: true,
        hostname: true, assetName: true, ipAddress: true, errorMessage: true,
        createdAt: true, updatedAt: true,
        uploadedBy: { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
        case: { select: { id: true, title: true, caseSeq: true } },
        _count: { select: { conversations: true, dnsQueries: true, findings: true, iocs: true } },
      },
    });

    return NextResponse.json({
      uploads: uploads.map((u) => ({ ...u, byteCount: u.byteCount.toString() })),
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── POST /api/pcap-analysis/uploads ────────────────────────────────────────
export async function POST(req: NextRequest) {
  try {
    const actor = await requireAuth(req);

    const formData  = await req.formData();
    const file      = formData.get("file");
    const hostname  = String(formData.get("hostname") ?? "").trim() || null;
    const assetName = String(formData.get("assetName") ?? "").trim() || null;
    const ipAddress = String(formData.get("ipAddress") ?? "").trim() || null;
    const notes     = String(formData.get("notes") ?? "").trim() || null;
    const orgId     = String(formData.get("organizationId") ?? "").trim() || null;
    const caseId    = String(formData.get("caseId") ?? "").trim() || null;

    if (!file || typeof file === "string" || !("arrayBuffer" in file)) {
      return NextResponse.json({ error: "missing_file", message: "Provide a file in the 'file' field." }, { status: 400 });
    }
    const ext = path.extname(file.name).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return NextResponse.json({ error: "invalid_file_type", message: "Only .pcap and .pcapng files are supported." }, { status: 400 });
    }
    if (!caseId) {
      return NextResponse.json({ error: "missing_case", message: "Every PCAP upload must be linked to a case. Select or create one before uploading." }, { status: 400 });
    }
    if (file.size > MAX_BYTES) {
      return NextResponse.json({ error: "file_too_large", message: "Maximum PCAP file size is 500 MB." }, { status: 413 });
    }

    const kase = await prisma.case.findUnique({ where: { id: caseId }, select: { id: true, status: true } });
    if (!kase) {
      return NextResponse.json({ error: "invalid_case", message: "The specified case does not exist." }, { status: 400 });
    }
    if (kase.status === "closed") {
      return NextResponse.json({ error: "case_closed", message: "This case is closed and cannot accept new uploads. Reopen it first." }, { status: 403 });
    }

    const buffer = Buffer.from(await file.arrayBuffer());
    const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");

    const upload = await prisma.pcapUpload.create({
      data: {
        filename: file.name,
        fileSize: buffer.length,
        sha256,
        status: "queued",
        hostname,
        assetName,
        ipAddress,
        notes,
        uploadedById: actor.id,
        organizationId: orgId ?? (actor.organizationIds[0] ?? null),
        caseId,
      },
    });

    const pcapDir = await getPcapDir();
    fs.mkdirSync(pcapDir, { recursive: true });
    const storagePath = path.join(pcapDir, `${upload.id}${ext}`);
    fs.writeFileSync(storagePath, buffer);

    const job = await getPcapQueue().add("process-pcap", { pcapUploadId: upload.id });

    const updated = await prisma.pcapUpload.update({
      where: { id: upload.id },
      data:  { storagePath, jobId: job.id ?? null },
    });

    return NextResponse.json({ upload: { ...updated, byteCount: updated.byteCount.toString() } }, { status: 201 });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[pcap-analysis/upload] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
