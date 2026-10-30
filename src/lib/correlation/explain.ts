/**
 * "Why This Matters" explanation for a grouped correlation entity.
 *
 * Two strictly separate layers:
 *  1. Deterministic facts — derived only from real DB rows (Evidence/Finding
 *     joined via the correlation's evidenceIds/investigationIds). Never
 *     contains interpretation, never overstates what's actually known.
 *  2. AI interpretation — optional, on-demand, generated from those same
 *     facts (never raw/unverified data), explicitly instructed to hedge
 *     and never claim certainty the facts don't support. Always rendered
 *     separately and labeled as AI-generated in the UI.
 */
import { prisma } from "@/lib/db/prisma";
import { generateAiCompletion, AiProviderError } from "@/lib/ai/provider";
import { getAiConfig } from "@/lib/settings/system";
import type { Prevalence, ExtraSourceRef } from "@/lib/correlation/engine";

export type GroupedCorrelationInput = {
  correlationType: string;
  value: string;
  hosts: string[];
  investigationIds: string[];
  evidenceIds: string[];
  distinctCaseCount: number;
  confidence: number;
  knownIoc: { reputation: number | null; threatType: string | null; malwareFamily: string | null } | null;
  // Optional: the Enterprise overlay ships its own copy of the list route,
  // and a Core update rebuilds with the previously installed overlay's
  // files — a required field here breaks that build until the overlay
  // catches up.
  prevalence?: Prevalence | null;
  /** PCAP / RAM / log analyses involved. Optional for the same reason as prevalence. */
  sources?: ExtraSourceRef[];
};

const SOURCE_LABEL: Record<string, string> = { pcap: "PCAP", ram: "RAM", log: "log" };

export type DeterministicFacts = {
  correlationType: string;
  value: string;
  hostCount: number;
  investigationCount: number;
  caseCount: number;
  confidence: number;
  knownIoc: GroupedCorrelationInput["knownIoc"];
  prevalence: Prevalence | null;
  /** Non-investigation sources by kind, e.g. [{ kind: "pcap", count: 1 }]. */
  analyses: { kind: string; count: number }[];
  // Only populated when the underlying correlation carries evidenceIds
  // (IOC-value correlations: hash/ip/domain/url/process/account) — hostname/
  // username/finding-type correlations have no linked Evidence rows.
  firstSeen: string | null;
  lastSeen: string | null;
  spanMinutes: number | null;
  processNames: string[];
  findingCategories: { category: string; count: number }[];
  topSeverity: string | null;
};

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * Whether a grouped entity is worth surfacing a "Why This Matters" section
 * for at all. A rarity-weighted score already accounts for how many hosts
 * share the value, so it alone (or a threat-intel match) decides; rows
 * scored without rarity keep the per-host rules.
 */
export function isSignificant(g: GroupedCorrelationInput): boolean {
  if (g.prevalence) return g.confidence >= 60 || !!g.knownIoc;
  return g.confidence >= 70 || !!g.knownIoc || g.distinctCaseCount > 1 || g.hosts.length >= 3;
}

export async function buildDeterministicFacts(g: GroupedCorrelationInput): Promise<DeterministicFacts> {
  const base: DeterministicFacts = {
    correlationType: g.correlationType,
    value: g.value,
    hostCount: g.hosts.length,
    investigationCount: g.investigationIds.length,
    caseCount: g.distinctCaseCount,
    confidence: g.confidence,
    knownIoc: g.knownIoc,
    prevalence: g.prevalence ?? null,
    analyses: countKinds(g.sources ?? []),
    firstSeen: null,
    lastSeen: null,
    spanMinutes: null,
    processNames: [],
    findingCategories: [],
    topSeverity: null,
  };

  if (g.evidenceIds.length === 0) return base;

  const evidence = await prisma.evidence.findMany({
    where: { id: { in: g.evidenceIds } },
    select: { timestamp: true, processName: true, findingId: true },
  });
  if (evidence.length === 0) return base;

  const timestamps = evidence.map((e) => e.timestamp).filter((t): t is Date => !!t);
  if (timestamps.length > 0) {
    const min = new Date(Math.min(...timestamps.map((t) => t.getTime())));
    const max = new Date(Math.max(...timestamps.map((t) => t.getTime())));
    base.firstSeen = min.toISOString();
    base.lastSeen = max.toISOString();
    base.spanMinutes = Math.round((max.getTime() - min.getTime()) / 60000);
  }

  base.processNames = Array.from(new Set(evidence.map((e) => e.processName).filter((p): p is string => !!p))).slice(0, 5);

  const findingIds = Array.from(new Set(evidence.map((e) => e.findingId)));
  if (findingIds.length > 0) {
    const findings = await prisma.finding.findMany({
      where: { id: { in: findingIds } },
      select: { category: true, severity: true },
    });
    const byCategory = new Map<string, number>();
    let topSeverity: string | null = null;
    for (const f of findings) {
      byCategory.set(f.category, (byCategory.get(f.category) ?? 0) + 1);
      const rank = SEVERITY_RANK[f.severity] ?? -1;
      if (topSeverity === null || rank > (SEVERITY_RANK[topSeverity] ?? -1)) topSeverity = f.severity;
    }
    base.findingCategories = Array.from(byCategory.entries())
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
    base.topSeverity = topSeverity;
  }

  return base;
}

function countKinds(sources: ExtraSourceRef[]): { kind: string; count: number }[] {
  const byKind = new Map<string, number>();
  for (const s of sources) byKind.set(s.kind, (byKind.get(s.kind) ?? 0) + 1);
  return Array.from(byKind.entries()).map(([kind, count]) => ({ kind, count }));
}

function joinAnd(items: string[]): string {
  return items.length <= 1 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

function formatSpan(minutes: number): string {
  if (minutes < 60) return `${minutes} minute${minutes !== 1 ? "s" : ""}`;
  if (minutes < 1440) return `${Math.round(minutes / 60)} hour(s)`;
  return `${Math.round(minutes / 1440)} day(s)`;
}

/** Pure-fact paragraph — zero interpretation, safe to always show. */
export function renderFactsNarrative(f: DeterministicFacts): string {
  const parts: string[] = [];
  const hosts = `${f.hostCount} host${f.hostCount !== 1 ? "s" : ""}`;
  const investigations = `${f.investigationCount} investigation${f.investigationCount !== 1 ? "s" : ""}`;
  const where = f.analyses.length === 0
    ? `${hosts} and ${investigations}`
    : `${hosts}, in ${joinAnd([
        ...(f.investigationCount > 0 ? [investigations] : []),
        ...f.analyses.map((a) => `${a.count} ${SOURCE_LABEL[a.kind] ?? a.kind} analys${a.count !== 1 ? "es" : "is"}`),
      ])}`;
  parts.push(`This value was observed across ${where}` + (f.caseCount > 1 ? ` spanning ${f.caseCount} cases.` : "."));
  if (f.firstSeen && f.lastSeen && f.spanMinutes !== null) {
    parts.push(
      f.spanMinutes === 0
        ? `All observed evidence shares the same timestamp (${new Date(f.firstSeen).toLocaleString()}).`
        : `Evidence was observed within a ${formatSpan(f.spanMinutes)} span (${new Date(f.firstSeen).toLocaleString()} to ${new Date(f.lastSeen).toLocaleString()}).`
    );
  }
  if (f.processNames.length > 0) {
    parts.push(`Associated process name${f.processNames.length !== 1 ? "s" : ""}: ${f.processNames.join(", ")}.`);
  }
  if (f.findingCategories.length > 0) {
    const cats = f.findingCategories.map((c) => `${c.category} (${c.count})`).join(", ");
    parts.push(`Linked finding categories: ${cats}${f.topSeverity ? ` — highest severity observed: ${f.topSeverity}` : ""}.`);
  }
  if (f.knownIoc) {
    const bits: string[] = [];
    if (f.knownIoc.reputation !== null) bits.push(`reputation ${f.knownIoc.reputation}/100`);
    if (f.knownIoc.threatType) bits.push(`threat type "${f.knownIoc.threatType}"`);
    if (f.knownIoc.malwareFamily) bits.push(`malware family "${f.knownIoc.malwareFamily}"`);
    parts.push(`This value matches a known threat-intelligence indicator${bits.length ? ` (${bits.join(", ")})` : ""}.`);
  }
  return parts.join(" ");
}

export async function generateAiInterpretation(facts: DeterministicFacts): Promise<{ text: string | null; unavailableReason?: string }> {
  const { enabled, ...aiConfig } = await getAiConfig();
  if (!enabled) return { text: null, unavailableReason: "Forensicator AI is not enabled (Settings > AI)." };

  const prompt = buildExplainPrompt(facts);
  try {
    const raw = await generateAiCompletion(aiConfig, prompt, { timeoutMs: 60_000 });
    return { text: raw.trim().slice(0, 1500) };
  } catch (err) {
    const message = err instanceof AiProviderError ? err.message : err instanceof Error ? err.message : "Unknown error";
    return { text: null, unavailableReason: message };
  }
}

function buildExplainPrompt(f: DeterministicFacts): string {
  const factLines: string[] = [
    `Correlation type: ${f.correlationType}`,
    `Value: ${f.value}`,
    `Host count: ${f.hostCount}`,
    `Investigation count: ${f.investigationCount}`,
    ...f.analyses.map((a) => `${SOURCE_LABEL[a.kind] ?? a.kind} analyses: ${a.count}`),
    `Distinct cases: ${f.caseCount}`,
    `Confidence score (deterministic, 0-100): ${f.confidence}`,
  ];
  if (f.prevalence) {
    factLines.push(
      `Prevalence: on ${f.prevalence.hosts} of ${f.prevalence.of} hosts on record ` +
      "(a value on most hosts is usually normal for the environment; rarity alone does not make a value malicious)"
    );
  }
  if (f.spanMinutes !== null) factLines.push(`Time span across observed evidence: ${formatSpan(f.spanMinutes)}`);
  if (f.processNames.length > 0) factLines.push(`Associated process names: ${f.processNames.join(", ")}`);
  if (f.findingCategories.length > 0) factLines.push(`Linked finding categories: ${f.findingCategories.map((c) => `${c.category} (${c.count})`).join(", ")}`);
  if (f.topSeverity) factLines.push(`Highest linked finding severity: ${f.topSeverity}`);
  if (f.knownIoc) {
    factLines.push(
      `Known threat-intel match: reputation=${f.knownIoc.reputation ?? "unknown"}, ` +
      `threatType=${f.knownIoc.threatType ?? "unknown"}, malwareFamily=${f.knownIoc.malwareFamily ?? "unknown"}`
    );
  }

  return (
    "You are assisting a DFIR (digital forensics and incident response) analyst reviewing a cross-investigation " +
    "correlation. Below are ONLY the verified, deterministic facts already established by the correlation engine — " +
    "do not assume any additional facts, do not invent evidence, and do not claim certainty this data doesn't " +
    "support. Write a short (2-4 sentence) 'why this matters' interpretation for the analyst, using hedged " +
    'language ("may indicate", "could suggest", "is consistent with") rather than definitive claims. If the facts ' +
    "are too sparse to say anything meaningful beyond restating them, say so plainly instead of speculating. " +
    "Respond with plain text only, no markdown, no JSON.\n\nFacts:\n" + factLines.join("\n")
  );
}
