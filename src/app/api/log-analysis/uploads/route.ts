import { NextRequest, NextResponse } from "next/server";
import { prisma }            from "@/lib/db/prisma";
import { requireAuth, orgWhere } from "@/lib/auth/api-guard";
import { processLogUpload }  from "@/lib/log-analysis/processor";
import { convertEvtx, decodeLogBuffer, isEvtx } from "@/lib/log-analysis/content";
import { getWinArtifactsPythonPath } from "@/lib/settings/system";
import { notArchived } from "@/lib/cases/archive";
import { canAccessOrg } from "@/lib/auth/org-access";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const MAX_BYTES = 50 * 1024 * 1024; // 50 MB of text
// Raw .evtx is binary and far denser than its XML rendering is useful to
// cap on — converted events are capped instead (see convertEvtx()).
const MAX_EVTX_BYTES = 256 * 1024 * 1024;

// ── GET /api/log-analysis/uploads ──────────────────────────────────────────
export async function GET(req: NextRequest) {
  try {
    const actor = await requireAuth(req);
    const where = orgWhere(actor);

    // Archived uploads (or ones in an archived case) are on the Archive page.
    const uploads = await prisma.logUpload.findMany({
      where: { ...where, ...notArchived() },
      orderBy: { createdAt: "desc" },
      take: 100,
      select: {
        id: true, filename: true, sourceType: true, status: true,
        eventCount: true, findingCount: true, hostname: true, assetName: true,
        ipAddress: true, errorMessage: true, createdAt: true, updatedAt: true,
        uploadedBy: { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
        case: { select: { id: true, title: true, caseSeq: true, status: true, archivedAt: true } },
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
    const looksEvtx = file.name.toLowerCase().endsWith(".evtx");
    if (file.size > (looksEvtx ? MAX_EVTX_BYTES : MAX_BYTES)) {
      return NextResponse.json({ error: "file_too_large", message: looksEvtx ? "Maximum .evtx file size is 256 MB." : "Maximum log file size is 50 MB." }, { status: 413 });
    }

    const kase = await prisma.case.findUnique({ where: { id: caseId }, select: { id: true, status: true, organizationId: true } });
    // Another organization's case is treated as nonexistent.
    if (!kase || !canAccessOrg(actor, kase.organizationId)) {
      return NextResponse.json({ error: "invalid_case", message: "The specified case does not exist." }, { status: 400 });
    }
    if (kase.status === "closed") {
      return NextResponse.json({ error: "case_closed", message: "This case is closed and cannot accept new uploads. Reopen it first." }, { status: 403 });
    }

    const buffer  = Buffer.from(await file.arrayBuffer());
    let content: string;
    let conversionNote: string | null = null;
    if (isEvtx(buffer, file.name)) {
      const converted = await convertEvtx(await getWinArtifactsPythonPath(), buffer);
      if (converted.status === "not_installed") {
        return NextResponse.json({ error: "evtx_unsupported", message: "python-evtx is not installed in the Windows Artifacts venv — see deploy/install-winartifacts-deps.sh." }, { status: 422 });
      }
      if (converted.status === "error") {
        return NextResponse.json({ error: "evtx_conversion_failed", message: `Could not read the .evtx file: ${converted.message}` }, { status: 422 });
      }
      content = converted.text;
      conversionNote = `Converted from EVTX: ${converted.events} event(s)${converted.failed ? `, ${converted.failed} unreadable record(s) skipped` : ""}${converted.truncated ? " — truncated at the conversion cap" : ""}.`;
    } else {
      content = decodeLogBuffer(buffer);
    }

    // Create upload record first
    const upload = await prisma.logUpload.create({
      data: {
        filename:      file.name,
        sourceType:    isEvtx(buffer, file.name) ? "windows-event" : sourceType,
        status:        "pending",
        hostname,
        assetName,
        ipAddress,
        notes:         conversionNote ? [notes, conversionNote].filter(Boolean).join("\n") : notes,
        uploadedById:  actor.id,
        organizationId: kase.organizationId,
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
