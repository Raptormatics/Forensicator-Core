/**
 * GET /api/sigma
 * Returns sigma rule match hits scoped to the authenticated user's org.
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { normalizeSeverity as mapLevel } from "@/lib/severity";

export type SigmaHit = {
  findingDbId:     string;
  investigationId: string;
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
  const limit       = Math.min(Number(searchParams.get("limit") ?? 200), 1000);
  const offset      = Number(searchParams.get("offset") ?? 0);

  const investigationScope = { ...scope, ...(caseId ? { caseId } : {}) };

  const findings = await prisma.finding.findMany({
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

  const hits: (SigmaHit & { investigationTitle: string; investigationHostname: string | null })[] = [];

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
