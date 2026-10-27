/**
 * GET /api/sigma
 * Sigma rule hits scoped to the authenticated user's org, from both
 * sources: Core's own Sigma rule library run on Log Analysis uploads
 * (LogFinding.sigmaRuleId — one hit per rule per upload) and the Sigma
 * detections a collector ran on the host (investigation findings — one hit
 * per matching event). ?source=core|collector narrows to one.
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { normalizeSeverity as mapLevel } from "@/lib/severity";

export type SigmaHit = {
  source:          "core" | "collector";
  findingDbId:     string;
  investigationId: string | null;
  logUploadId:     string | null;
  logUploadName:   string | null;
  eventCount:      number;
  hostname:        string | null;
  ruleTitle:       string;
  ruleLevel:       string; // mapped to new priority label
  ruleLevelRaw:    string; // original sigma level
  ruleTags:        string | null;
  ruleFile:        string | null;
  eventId:         string | null;
  user:            string | null;
  process:         string | null;
  commandLine:     string | null;
  logName:         string | null;
  message:         string | null;
  ruleId:          string | null;
  time:            string | null;
};

export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return (e as AuthError).toResponse(); throw e; }

  const scope = orgWhere(actor);
  const { searchParams } = new URL(req.url);
  const q           = (searchParams.get("q") ?? "").toLowerCase().trim();
  const levelFilter = (searchParams.get("level") ?? "").toLowerCase();
  const caseId       = searchParams.get("caseId") ?? undefined;
  const source      = searchParams.get("source") ?? "";
  const limit       = Math.min(Number(searchParams.get("limit") ?? 200), 1000);
  const offset      = Number(searchParams.get("offset") ?? 0);

  const investigationScope = { ...scope, ...(caseId ? { caseId } : {}) };

  const hits: (SigmaHit & { investigationTitle: string; investigationHostname: string | null })[] = [];

  // Core's Sigma rule library, on Log Analysis uploads.
  if (source !== "collector") {
    const logFindings = await prisma.logFinding.findMany({
      where: {
        sigmaRuleId: { not: null },
        upload: { ...scope, ...(caseId ? { caseId } : {}) },
      },
      select: {
        id: true, title: true, severity: true, eventCount: true, firstSeen: true, matchedValue: true, details: true,
        upload: { select: { id: true, filename: true, hostname: true, sourceType: true } },
      },
      orderBy: { createdAt: "desc" },
      take: 5000,
    });
    for (const f of logFindings) {
      const d = (f.details ?? {}) as { level?: string; tags?: string[]; sigmaId?: string };
      const raw = (d.level ?? f.severity).toLowerCase();
      if (levelFilter && raw !== levelFilter && mapLevel(raw).toLowerCase() !== levelFilter.toLowerCase()) continue;
      if (q && ![f.title, f.matchedValue, f.upload.filename, f.upload.hostname].filter(Boolean).join(" ").toLowerCase().includes(q)) continue;
      hits.push({
        source: "core",
        findingDbId: f.id,
        investigationId: null,
        investigationTitle: f.upload.filename,
        investigationHostname: f.upload.hostname,
        logUploadId: f.upload.id,
        logUploadName: f.upload.filename,
        eventCount: f.eventCount,
        hostname: f.upload.hostname,
        ruleTitle: f.title,
        ruleLevel: mapLevel(raw),
        ruleLevelRaw: raw,
        ruleTags: d.tags?.join(", ") || null,
        ruleFile: null,
        eventId: null,
        user: null,
        process: null,
        commandLine: f.matchedValue,
        logName: f.upload.sourceType,
        message: null,
        ruleId: d.sigmaId ?? null,
        time: f.firstSeen ? f.firstSeen.toISOString() : null,
      });
    }
  }

  const findings = source === "core" ? [] : await prisma.finding.findMany({
    where: {
      ...(Object.keys(investigationScope).length > 0 ? { investigation: investigationScope } : {}),
      OR: [
        { sourceCategory: "sigma" },
        { findingType: { contains: "sigma", mode: "insensitive" } },
        { findingType: { contains: "Sigma Rule", mode: "insensitive" } },
      ],
    },
    select: {
      id:              true,
      investigationId: true,
      hostName:        true,
      data:            true,
      investigation:   { select: { title: true, hostname: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  for (const f of findings) {
    const data     = f.data as Record<string, unknown>;
    const evidence = Array.isArray(data?.evidence) ? data.evidence : [];

    for (const row of evidence as Record<string, unknown>[]) {
      const ruleTitle   = str(row.rule_title) ?? str(row.title) ?? "Unknown Rule";
      const ruleLevelRaw = (str(row.rule_level) ?? str(row.level) ?? "informational").toLowerCase();
      const ruleLevel = ruleLevelRaw; // kept here for filter comparison (raw sigma level)

      if (levelFilter && ruleLevelRaw !== levelFilter && mapLevel(ruleLevelRaw).toLowerCase() !== levelFilter.toLowerCase()) continue;
      if (q) {
        const haystack = [ruleTitle, str(row.process), str(row.user), str(row.event_id), str(row.log_name)]
          .filter(Boolean).join(" ").toLowerCase();
        if (!haystack.includes(q)) continue;
      }

      hits.push({
        source:                "collector",
        logUploadId:           null,
        logUploadName:         null,
        eventCount:            1,
        findingDbId:           f.id,
        investigationId:       f.investigationId,
        investigationTitle:    f.investigation.title,
        investigationHostname: f.investigation.hostname,
        hostname:              f.hostName,
        ruleTitle,
        ruleLevel:    mapLevel(ruleLevel),
        ruleLevelRaw: ruleLevel,
        ruleTags:    str(row.rule_tags) ?? null,
        ruleFile:    str(row.rule_file) ?? null,
        eventId:     str(row.event_id) ?? null,
        user:        str(row.user)     ?? null,
        process:     str(row.process)  ?? null,
        commandLine: str(row.command_line) ?? null,
        logName:     str(row.log_name) ?? null,
        message:     str(row.message)  ?? null,
        ruleId:      str(row.rule_id)  ?? null,
        time:        str(row.time)     ?? null,
      });
    }
  }

  const total = hits.length;
  const page  = hits.slice(offset, offset + limit);

  return NextResponse.json({ hits: page, total });
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}
