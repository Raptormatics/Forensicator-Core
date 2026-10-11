import { NextRequest, NextResponse } from "next/server";
import { prisma }            from "@/lib/db/prisma";
import { requireAuth, orgWhere } from "@/lib/auth/api-guard";
import { processLogUpload }  from "@/lib/log-analysis/processor";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const MAX_BYTES = 50 * 1024 * 1024; // 50 MB

// ── GET /api/log-analysis/uploads ──────────────────────────────────────────
export async function GET(req: NextRequest) {
  try {
    const actor = await requireAuth(req);
    const where = orgWhere(actor);

    const uploads = await prisma.logUpload.findMany({
      where: { ...where },
      orderBy: { createdAt: "desc" },
      take: 100,
      select: {
        id: true, filename: true, sourceType: true, status: true,
        eventCount: true, findingCount: true, hostname: true, assetName: true,
        ipAddress: true, errorMessage: true, createdAt: true, updatedAt: true,
        uploadedBy: { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
        case: { select: { id: true, title: true, caseSeq: true } },
        _count: { select: { findings: true, iocs: true } },
      },
    });

    return NextResponse.json({ uploads });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── POST /api/log-analysis/uploads ─────────────────────────────────────────
export async function POST(req: NextRequest) {
  try {
    const actor = await requireAuth(req);

    const formData   = await req.formData();
    const file       = formData.get("file");
    const sourceType = String(formData.get("sourceType") ?? "").trim();
    const hostname   = String(formData.get("hostname") ?? "").trim() || null;
    const assetName  = String(formData.get("assetName") ?? "").trim() || null;
    const ipAddress  = String(formData.get("ipAddress") ?? "").trim() || null;
    const notes      = String(formData.get("notes") ?? "").trim() || null;
    const orgId      = String(formData.get("organizationId") ?? "").trim() || null;
    const caseId     = String(formData.get("caseId") ?? "").trim() || null;

    if (!file || typeof file === "string" || !("arrayBuffer" in file)) {
      return NextResponse.json({ error: "missing_file", message: "Provide a file in the 'file' field." }, { status: 400 });
    }
    if (!sourceType) {
      return NextResponse.json({ error: "missing_source_type", message: "Provide a sourceType." }, { status: 400 });
    }
    if (!caseId) {
      return NextResponse.json({ error: "missing_case", message: "Every log upload must be linked to a case. Select or create one before uploading." }, { status: 400 });
    }
    if (file.size > MAX_BYTES) {
      return NextResponse.json({ error: "file_too_large", message: "Maximum log file size is 50 MB." }, { status: 413 });
    }

    const kase = await prisma.case.findUnique({ where: { id: caseId }, select: { id: true, status: true } });
    if (!kase) {
      return NextResponse.json({ error: "invalid_case", message: "The specified case does not exist." }, { status: 400 });
    }
    if (kase.status === "closed") {
      return NextResponse.json({ error: "case_closed", message: "This case is closed and cannot accept new uploads. Reopen it first." }, { status: 403 });
    }

    const buffer  = Buffer.from(await file.arrayBuffer());
    const content = buffer.toString("utf-8");

    // Create upload record first
    const upload = await prisma.logUpload.create({
      data: {
        filename:      file.name,
        sourceType,
        status:        "pending",
        hostname,
        assetName,
        ipAddress,
        notes,
        uploadedById:  actor.id,
        organizationId: orgId ?? (actor.organizationIds[0] ?? null),
        caseId,
      },
    });

    // Process synchronously in the same request (up to 50MB is acceptable for server-side parsing)
    await processLogUpload(upload.id, content);

    const updated = await prisma.logUpload.findUnique({ where: { id: upload.id } });
    return NextResponse.json({ upload: updated }, { status: 201 });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[log-analysis/upload] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
