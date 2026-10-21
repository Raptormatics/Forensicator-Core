export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { normalizeSeverity, severityRank } from "@/lib/severity";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { guardCaseOpen } from "@/lib/cases/case-lock";

type Params = { params: Promise<{ id: string }> };

type Stage = {
  stage: number;
  label: string;
  tactic: string;
  findings: { id: string; title: string; severity: string; category: string }[];
};

const TACTIC_MAP: Record<string, { stage: number; label: string; tactic: string }> = {
  "initial access":   { stage: 1, label: "Initial Access",   tactic: "TA0001" },
  "execution":        { stage: 2, label: "Execution",         tactic: "TA0002" },
  "persistence":      { stage: 3, label: "Persistence",       tactic: "TA0003" },
  "privilege":        { stage: 4, label: "Privilege Esc.",    tactic: "TA0004" },
  "defense evasion":  { stage: 5, label: "Defense Evasion",   tactic: "TA0005" },
  "credential":       { stage: 6, label: "Credential Access", tactic: "TA0006" },
  "discovery":        { stage: 7, label: "Discovery",         tactic: "TA0007" },
  "lateral":          { stage: 8, label: "Lateral Movement",  tactic: "TA0008" },
  "exfil":            { stage: 9, label: "Exfiltration",      tactic: "TA0010" },
  "command":          { stage: 9, label: "C2",                tactic: "TA0011" },
  "impact":           { stage: 10, label: "Impact",           tactic: "TA0040" },
};

// POST /api/investigations/[id]/attack-path/generate
export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const inv = await prisma.investigation.findFirst({ where: { id: params.id, ...orgWhere(actor) } });
  if (!inv) return NextResponse.json({ error: "Investigation not found" }, { status: 404 });
  const locked = await guardCaseOpen({ investigationId: inv.id }, "regenerating its attack path");
  if (locked) return locked;

  // `severity` is free-text (Important/Notable/...), so DB orderBy would sort
  // alphabetically — sort by rank in JS instead, most-severe-first.
  const findings = (await prisma.finding.findMany({
    where: { investigationId: params.id },
    select: { id: true, severity: true, category: true, data: true },
  })).sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  // Map findings to attack stages
  const stageMap = new Map<number, Stage>();

  for (const f of findings) {
    const cat = (f.category ?? "").toLowerCase();
    const fData = f.data as Record<string, unknown>;
    const fTitle = String(fData.title ?? fData.findingType ?? "");
    let matched: { stage: number; label: string; tactic: string } | null = null;

    for (const [keyword, def] of Object.entries(TACTIC_MAP)) {
      if (cat.includes(keyword) || fTitle.toLowerCase().includes(keyword)) {
        matched = def;
        break;
      }
    }

    if (!matched) {
      // Default uncategorised to discovery
      matched = { stage: 7, label: "Discovery", tactic: "TA0007" };
    }

    if (!stageMap.has(matched.stage)) {
      stageMap.set(matched.stage, { ...matched, findings: [] });
    }
    stageMap.get(matched.stage)!.findings.push({
      id: f.id, title: fTitle, severity: normalizeSeverity(f.severity), category: f.category ?? "",
    });
  }

  const stages = Array.from(stageMap.values()).sort((a, b) => a.stage - b.stage);

  const summary = stages.length === 0
    ? "No attack stages identified."
    : `Attack chain spans ${stages.length} stage(s): ${stages.map((s) => s.label).join(" → ")}`;

  const existing = await prisma.attackPath.findFirst({ where: { investigationId: params.id } });

  const ap = existing
    ? await prisma.attackPath.update({
        where: { id: existing.id },
        data: { stages: stages as object[], summary, generatedAt: new Date(), status: "complete" },
      })
    : await prisma.attackPath.create({
        data: { investigationId: params.id, stages: stages as object[], summary, status: "complete", generatedAt: new Date() },
      });

  return NextResponse.json({ attackPath: ap });
}
