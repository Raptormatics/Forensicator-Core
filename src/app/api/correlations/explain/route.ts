export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError, orgWhere } from "@/lib/auth/api-guard";
import { fetchRawRows, groupRows, lookupKnownIocs, IOC_CORRELATION_TYPES } from "@/lib/correlation/group";
import {
  buildDeterministicFacts, renderFactsNarrative, generateAiInterpretation,
  type GroupedCorrelationInput,
} from "@/lib/correlation/explain";

/**
 * POST /api/correlations/explain — on-demand AI interpretation for one
 * grouped correlation entity. Re-derives the group server-side from
 * (correlationType, value) rather than trusting client-submitted facts, so
 * the AI is always prompted from data we actually verified ourselves.
 */
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const body = await req.json().catch(() => ({}));
  const correlationType = typeof body.correlationType === "string" ? body.correlationType : undefined;
  const value = typeof body.value === "string" ? body.value : undefined;
  if (!correlationType || !value) {
    return NextResponse.json({ error: "correlationType and value are required" }, { status: 400 });
  }

  const caseScope = orgWhere(actor);
  const caseFilter = Object.keys(caseScope).length > 0 ? { case: { ...caseScope } } : {};
  const rows = await fetchRawRows({ ...caseFilter, correlationType, value });
  const groups = groupRows(rows);
  const g = groups.get(`${correlationType}::${value}`);
  if (!g) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const knownIoc = IOC_CORRELATION_TYPES.has(correlationType)
    ? (await lookupKnownIocs([value])).get(value.toLowerCase()) ?? null
    : null;

  const groupInput: GroupedCorrelationInput = {
    correlationType, value,
    hosts: Array.from(g.hosts), investigationIds: Array.from(g.investigationIds), evidenceIds: Array.from(g.evidenceIds),
    distinctCaseCount: g.cases.size, confidence: g.confidence, knownIoc, prevalence: g.prevalence, sources: g.sources,
  };

  const facts = await buildDeterministicFacts(groupInput);
  const narrative = renderFactsNarrative(facts);
  const { text, unavailableReason } = await generateAiInterpretation(facts);

  return NextResponse.json({ facts, deterministicNarrative: narrative, aiInterpretation: text, aiUnavailableReason: unavailableReason ?? null });
}
