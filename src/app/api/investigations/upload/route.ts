import { NextRequest, NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { ZodError } from "zod";
import { randomUUID, createHash } from "crypto";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { normalizeSeverity } from "@/lib/severity";
import { uploadMetadataSchema } from "@/lib/schemas/upload";
import { buildFindingSearchText, extractHostname, extractRiskScore } from "@/lib/upload/finding-index";
import {
  categoryCounts,
  deriveInvestigationTitle,
  duplicateFindingIds,
  metadataString,
  severityCounts
} from "@/lib/upload/summary";
import { parseInvestigationZip, UploadValidationError } from "@/lib/upload/zip";
import { extractEvidence, extractTimelineEvents } from "@/lib/upload/evidence-extractor";
import { extractAndUpsertIocs, type NewIocRecord } from "@/lib/intelligence/investigation-ioc-extract";
import { autoEnrichNewIocs } from "@/lib/intelligence/auto-enrich";

// dispatchSiemExport lives in the Enterprise overlay (@/lib/siem), not in
// Forensicator Core — loaded via dynamic import below so this route works
// whether or not that module is present on disk. IOC extraction and
// auto-enrichment used to be gated the same way; both are now native Core
// modules (see src/lib/intelligence/), imported directly above instead.
//
// The import() below uses a non-literal specifier (a const, not the
// string inlined directly) — with a literal string, TypeScript resolves
// the module at compile time and hard-fails the build when it's absent
// (exactly the "Cannot find module" this pattern exists to tolerate at
// runtime instead). A variable specifier isn't statically resolvable, so
// tsc skips that check and only the dynamic, catchable runtime import
// remains.
const SIEM_DISPATCH_MODULE = "@/lib/siem/dispatch";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const upload = formData.get("file");

    if (!isUploadedFile(upload)) {
      return NextResponse.json(
        { error: "missing_file", message: "Upload a ZIP archive in the form field named file." },
        { status: 400 }
      );
    }

    if (upload.size > MAX_UPLOAD_BYTES) {
      return NextResponse.json(
        { error: "file_too_large", message: "ZIP uploads are limited to 100 MB for the MVP." },
        { status: 413 }
      );
    }

    // Validate case (mandatory — every upload must belong to a case).
    const caseId = stringFormValue(formData.get("caseId"));
    if (!caseId) {
      return NextResponse.json(
        { error: "missing_case", message: "Every upload must be linked to a case. Select or create one before uploading." },
        { status: 400 }
      );
    }
    const kase = await prisma.case.findUnique({ where: { id: caseId }, select: { id: true, status: true } });
    if (!kase) {
      return NextResponse.json(
        { error: "invalid_case", message: "The specified case does not exist." },
        { status: 400 }
      );
    }
    if (kase.status === "closed") {
      return NextResponse.json(
        { error: "case_closed", message: "This case is closed and cannot accept new uploads. Reopen it first." },
        { status: 403 }
      );
    }

    const buffer = Buffer.from(await upload.arrayBuffer());
    // Hash the raw archive bytes as uploaded — before any parsing/extraction —
    // so it matches whatever the collector hashed on the endpoint at collection time.
    const archiveSha256 = createHash("sha256").update(buffer).digest("hex");
    const parsed = parseInvestigationZip(buffer);
    const formMetadata = parseFormMetadata(formData.get("metadata"));
    const metadata = uploadMetadataSchema.parse({
      ...parsed.metadata,
      ...formMetadata,
      uploaded_archive_name: upload.name,
      uploaded_archive_size: upload.size
    });

    // Pull strongly-typed fields from the parsed investigation metadata.
    const invMeta = parsed.investigationMetadata;

    const duplicates = duplicateFindingIds(parsed.findings.map((finding) => finding.data));

    if (duplicates.length > 0) {
      throw new UploadValidationError("Duplicate finding_id values are not allowed within one investigation.", [
        {
          path: "investigation/<category>/*.json",
          message: `Duplicate finding_id values: ${duplicates.join(", ")}`
        }
      ]);
    }

    const firstFinding = parsed.findings[0]?.data;
    const hostname =
      stringFormValue(formData.get("hostname")) ??
      invMeta.hostname ??
      metadataString(metadata, "hostname") ??
      (firstFinding ? extractHostname(firstFinding) : undefined) ??
      null;

    const title =
      stringFormValue(formData.get("title")) ??
      invMeta.title ??
      deriveInvestigationTitle({ ...metadata, hostname }, firstFinding);

    const description = stringFormValue(formData.get("description"));
    const actor = await getUploadActor(request);
    const bySeverity = severityCounts(parsed.findings.map((finding) => finding.data));
    const byCategory = categoryCounts(parsed.findings.map((finding) => finding.data));

    // Step 1 — create the investigation row atomically, linked to its case
    // directly (an investigation belongs to at most one case).
    const investigation = await prisma.investigation.create({
      data: {
        title,
        description,
        hostname,
        metadata: metadata as Prisma.InputJsonValue,
        archiveSha256,
        findingCount: parsed.findings.length,
        uploadedById: actor.id,
        // Tag investigation with actor's primary org for isolation
        organizationId: actor.organizationIds[0] ?? null,
        investigationSourceId: invMeta.investigation_id ?? null,
        username: invMeta.username ?? null,
        osInfo: invMeta.os ? (invMeta.os as Prisma.InputJsonValue) : Prisma.DbNull,
        tags: invMeta.findingtags ?? [],
        detectionStats: invMeta.statistics
          ? (invMeta.statistics as Prisma.InputJsonValue)
          : Prisma.DbNull,
        caseId,
      }
    });

    // Step 2 — pre-assign UUIDs so we can build evidence/timeline rows without
    // needing createManyAndReturn (which requires Prisma preview features).
    const findingsWithIds = parsed.findings.map((f) => ({
      ...f,
      dbId: randomUUID() as string,
    }));

    // Insert findings in batches. On failure, clean up the investigation row.
    try {
      const BATCH = 200;
      for (let i = 0; i < findingsWithIds.length; i += BATCH) {
        await prisma.finding.createMany({
          data: findingsWithIds.slice(i, i + BATCH).map(({ data, path, sourceCategory, dbId }) => ({
            id: dbId,
            investigationId: investigation.id,
            findingId: data.finding_id ?? dbId,
            findingType: data.finding_type,
            category: data.category ?? "unknown",
            severity: normalizeSeverity(data.severity ?? "informational"),
            hostName: extractHostname(data),
            riskScore: extractRiskScore(data),
            evidenceCount: data.evidence.length,
            data: data as Prisma.InputJsonValue,
            searchText: buildFindingSearchText(data),
            tags: Array.isArray((data as Record<string, unknown>).findingtags)
              ? ((data as Record<string, unknown>).findingtags as string[]).filter((t) => typeof t === "string")
              : [],
            // The collector's own ai_analysis.status defaults to "pending"
            // whenever ITS local AI (config.json's "ai" block) is off,
            // which is the common case — that's "the collector never
            // analyzed this," not "queue this on Enterprise right now."
            // Only "complete"/"failed" carry a real, already-done result
            // worth reflecting as-is; anything else means Enterprise
            // hasn't queued anything either, so it starts at its own
            // Finding.aiStatus default.
            aiStatus: normalizeUploadAiStatus(data.ai_analysis?.status as string | undefined),
            aiSummary: (data.ai_analysis?.summary as string | undefined) ?? null,
            aiConfidence: (data.ai_analysis?.confidence as number | undefined) ?? null,
            sourcePath: path,
            sourceCategory: sourceCategory ?? null,
          })),
        });
      }
    } catch (findingError) {
      await prisma.investigation.delete({ where: { id: investigation.id } }).catch(() => {});
      throw findingError;
    }

    // Step 3 — extract and insert normalised evidence + timeline events.
    // These are non-fatal: if the migration hasn't run yet (tables don't exist)
    // the findings upload still succeeds.
    let evidenceCount = 0;
    let timelineCount = 0;
    const enrichmentWarnings: string[] = [
      // surface any finding files that were skipped during zip parsing
      ...parsed.skippedFiles.map((s) => `Skipped ${s.path}: ${s.message}`),
    ];

    try {
      const evidenceRows = [];
      const timelineRows = [];

      for (const { data, sourceCategory, dbId } of findingsWithIds) {
        if (data.evidence.length > 0) {
          evidenceRows.push(
            ...extractEvidence(data, investigation.id, dbId, sourceCategory ?? null)
          );
        }
        timelineRows.push(
          ...extractTimelineEvents(data, investigation.id, dbId)
        );
      }

      const EV_BATCH = 500;
      for (let i = 0; i < evidenceRows.length; i += EV_BATCH) {
        await prisma.evidence.createMany({ data: evidenceRows.slice(i, i + EV_BATCH) });
      }
      evidenceCount = evidenceRows.length;

      const TL_BATCH = 500;
      for (let i = 0; i < timelineRows.length; i += TL_BATCH) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        await prisma.timelineEvent.createMany({ data: timelineRows.slice(i, i + TL_BATCH) as any[] });
      }
      timelineCount = timelineRows.length;
    } catch (enrichmentError) {
      // Log but do not fail — evidence tables may not be migrated yet.
      const msg = enrichmentError instanceof Error ? enrichmentError.message : String(enrichmentError);
      console.warn("[upload] Evidence/timeline enrichment skipped:", msg);
      enrichmentWarnings.push(msg);
    }

    // Step 4 — extract IOC / hash records from relevant findings and upsert into IocRecord.
    // This populates the IOC Intelligence page without requiring a separate enrichment step.
    // Newly-created (not previously-seen) records are auto-enriched below —
    // the free local URLhaus feed match always, live providers capped/queued.
    // IOC extraction/auto-enrichment are native Core features now (see
    // src/lib/intelligence/) — still wrapped in try/catch so a genuine bug
    // here (bad data, a transient enrichment-provider error) degrades to a
    // logged warning rather than failing the whole upload; this is no
    // longer about tolerating the module's mere absence.
    let newIocRecords: NewIocRecord[] = [];
    try {
      newIocRecords = await extractAndUpsertIocs(findingsWithIds);
    } catch (iocError) {
      console.warn("[upload] IocRecord extraction skipped:", iocError instanceof Error ? iocError.message : iocError);
    }

    let iocFeedMatches = 0;
    let iocQueuedForEnrichment = 0;
    if (newIocRecords.length > 0) {
      try {
        const { feedMatches, queued } = await autoEnrichNewIocs(newIocRecords, actor.organizationIds[0]);
        iocFeedMatches = feedMatches;
        iocQueuedForEnrichment = queued;
      } catch (enrichErr) {
        console.warn("[upload] Auto-enrichment skipped:", enrichErr instanceof Error ? enrichErr.message : enrichErr);
      }
    }

    // Auto-sync HostProfile so the Hosts page shows data immediately
    if (investigation.hostname) {
      try {
        const hn = investigation.hostname;
        const invs = await prisma.investigation.findMany({
          where: { hostname: hn },
          select: { id: true, createdAt: true, findingCount: true, detectionStats: true, osInfo: true },
          orderBy: { createdAt: "asc" },
        });
        const dsOf = (i: typeof invs[0]) => (i.detectionStats as Record<string, number> | null) ?? {};
        const usbCount  = await prisma.finding.count({ where: { investigation: { hostname: hn }, category: { contains: "usb", mode: "insensitive" } } });
        const persCount = await prisma.finding.count({ where: { investigation: { hostname: hn }, OR: [{ category: { contains: "persist", mode: "insensitive" } }, { category: { contains: "service", mode: "insensitive" } }, { category: { contains: "startup", mode: "insensitive" } }] } });
        const profileData = {
          firstSeen:          invs[0].createdAt,
          lastSeen:           invs[invs.length - 1].createdAt,
          investigationCount: invs.length,
          findingCount:       invs.reduce((s, i) => s + (i.findingCount ?? 0), 0),
          criticalCount:      invs.reduce((s, i) => s + (dsOf(i).critical_detections ?? 0), 0),
          highCount:          invs.reduce((s, i) => s + (dsOf(i).high_detections ?? 0), 0),
          iocMatchCount:      invs.reduce((s, i) => s + (dsOf(i).ioc_detections ?? 0), 0),
          usbActivity:        usbCount,
          persistenceEvents:  persCount,
          riskScore:          0,
          osInfo:             invs[invs.length - 1].osInfo ?? undefined,
        };
        await prisma.hostProfile.upsert({
          where:  { hostname: hn },
          update: profileData,
          create: { hostname: hn, ...profileData },
        });
      } catch (e) {
        console.warn("[upload] HostProfile auto-sync skipped:", e instanceof Error ? e.message : e);
      }
    }

    // Dispatch SIEM export jobs (fire-and-forget — errors are logged, never
    // thrown). @/lib/siem lives in the Enterprise overlay, not Core — the
    // dynamic import's own rejection (module absent) is caught the same way
    // as any other dispatch failure, so this is a silent no-op on Core.
    if (investigation.organizationId) {
      import(SIEM_DISPATCH_MODULE)
        .then(({ dispatchSiemExport }) =>
          dispatchSiemExport(investigation.id, investigation.organizationId!, "findings_generated")
        )
        .catch((e) => console.warn("[upload] SIEM dispatch skipped:", e instanceof Error ? e.message : e));
    }

    return NextResponse.json(
      {
        investigation: {
          id: investigation.id,
          title: investigation.title,
          hostname: investigation.hostname,
          username: investigation.username,
          tags: investigation.tags,
          os: investigation.osInfo,
          detection_stats: investigation.detectionStats,
          finding_count: parsed.findings.length,
          archive_sha256: investigation.archiveSha256,
          created_at: investigation.createdAt.toISOString(),
          url: `/investigations/${investigation.id}`
        },
        findings: {
          total: parsed.findings.length,
          by_severity: bySeverity,
          by_category: byCategory
        },
        enrichment: {
          evidence_rows: evidenceCount,
          timeline_events: timelineCount,
          ioc_feed_matches: iocFeedMatches > 0 ? iocFeedMatches : undefined,
          ioc_queued_for_enrichment: iocQueuedForEnrichment > 0 ? iocQueuedForEnrichment : undefined,
          warnings: enrichmentWarnings.length > 0 ? enrichmentWarnings : undefined,
        },
      },
      { status: 201 }
    );
  } catch (error) {
    if (error instanceof UploadValidationError) {
      return NextResponse.json(
        { error: "invalid_upload", message: error.message, issues: error.issues },
        { status: 400 }
      );
    }

    if (error instanceof SyntaxError) {
      return NextResponse.json({ error: "invalid_json", message: error.message }, { status: 400 });
    }

    // Auth failures from getUploadActor
    if (error instanceof AuthError) {
      return error.toResponse();
    }

    if (error instanceof ZodError) {
      return NextResponse.json(
        { error: "invalid_upload", message: "Upload metadata failed validation.", issues: error.flatten() },
        { status: 400 }
      );
    }

    const detail = error instanceof Error
      ? { message: error.message, name: error.name }
      : { message: String(error) };
    console.error("[upload] Upload failed:", error);
    return NextResponse.json(
      {
        error: "upload_failed",
        message: detail.message,
        detail,
      },
      { status: 500 }
    );
  }
}

async function getUploadActor(request: NextRequest) {
  return getActorOrThrow(request);
}

function parseFormMetadata(value: FormDataEntryValue | null) {
  if (typeof value !== "string" || !value.trim()) {
    return {};
  }

  return uploadMetadataSchema.parse(JSON.parse(value));
}

function stringFormValue(value: FormDataEntryValue | null) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

/**
 * Only "complete"/"failed" from the collector represent a real, already-run
 * analysis worth carrying over as-is. Everything else ("pending" — the
 * collector's own default when its local AI is off, "processing", or
 * absent entirely) means no analysis has actually happened yet, so the row
 * starts at "not_queued" rather than a value that looks like it's already
 * in Enterprise's own queue.
 */
function normalizeUploadAiStatus(collectorStatus: string | undefined): string {
  return collectorStatus === "complete" || collectorStatus === "failed" ? collectorStatus : "not_queued";
}

function isUploadedFile(value: FormDataEntryValue | null): value is File {
  return (
    typeof value === "object" &&
    value !== null &&
    "arrayBuffer" in value &&
    "name" in value &&
    "size" in value
  );
}

