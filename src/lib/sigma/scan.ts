/**
 * Runs Core's Sigma rule library (SigmaRule, src/lib/sigma/sync.ts) against
 * Log Analysis events and stores each matching rule as a LogFinding
 * (sigmaRuleId set; details holds the rule's metadata and the first
 * matching lines). Called for every new upload by processLogUpload(), and
 * on demand for an existing upload (POST /api/log-analysis/uploads/[id]/sigma).
 */
import { prisma } from "@/lib/db/prisma";
import { SigmaEventView, SigmaRuleIndex, ruleLogsourceKey } from "./engine";
import type { CompiledSigmaRule } from "./compile";

const SAMPLES_PER_RULE = 20;

type RuleInfo = {
  id: string; sigmaId: string; title: string; description: string | null; level: string; status: string | null;
  tags: string[]; references: string[]; falsePositives: string[]; product: string | null; category: string | null; service: string | null;
};

let cached: { stamp: string; index: SigmaRuleIndex; rules: Map<string, RuleInfo> } | null = null;

/** Enabled, supported, covered rules, compiled into an index — rebuilt only when the library changes. */
export async function loadSigmaIndex(): Promise<{ index: SigmaRuleIndex; rules: Map<string, RuleInfo> } | null> {
  const where = { enabled: true, supported: true, covered: true };
  const agg = await prisma.sigmaRule.aggregate({ where, _count: { _all: true }, _max: { updatedAt: true } });
  if (agg._count._all === 0) return null;
  const stamp = `${agg._count._all}:${agg._max.updatedAt?.getTime() ?? 0}`;
  if (cached?.stamp === stamp) return cached;
  const rows = await prisma.sigmaRule.findMany({
    where,
    select: { id: true, sigmaId: true, title: true, description: true, level: true, status: true, tags: true, references: true,
      falsePositives: true, product: true, category: true, service: true, compiled: true },
  });
  const index = new SigmaRuleIndex(rows.filter((r) => r.compiled).map((r) => ({
    id: r.id, key: ruleLogsourceKey(r.product, r.category, r.service), compiled: r.compiled as unknown as CompiledSigmaRule,
  })));
  const rules = new Map(rows.map(({ compiled: _c, ...r }) => [r.id, r]));
  cached = { stamp, index, rules };
  return cached;
}

export type SigmaScanEvent = { lineNumber: number; timestamp: Date | null; raw: string; normalized: unknown };

type Hit = { count: number; first: Date | null; last: Date | null; samples: { line: number; time: string | null; text: string }[] };

function eventSummary(ev: SigmaEventView): string {
  for (const f of ["CommandLine", "ScriptBlockText", "Image", "TargetFilename", "QueryName", "ImagePath", "TargetObject"]) {
    const v = ev.isEventXml ? ev.get(f)?.[0] : undefined;
    if (v) return `${f}: ${v}`;
  }
  return ev.raw.length > 600 ? `${ev.raw.slice(0, 600)}…` : ev.raw;
}

export class SigmaScanner {
  private hits = new Map<string, Hit>();
  scanned = 0;
  constructor(private readonly index: SigmaRuleIndex) {}

  add(e: SigmaScanEvent) {
    this.scanned++;
    const view = new SigmaEventView({ raw: e.raw, normalized: e.normalized });
    if (view.keys.length === 0) return;
    for (const id of this.index.match(view)) {
      let h = this.hits.get(id);
      if (!h) { h = { count: 0, first: null, last: null, samples: [] }; this.hits.set(id, h); }
      h.count++;
      if (e.timestamp) {
        if (!h.first || e.timestamp < h.first) h.first = e.timestamp;
        if (!h.last || e.timestamp > h.last) h.last = e.timestamp;
      }
      if (h.samples.length < SAMPLES_PER_RULE) {
        h.samples.push({ line: e.lineNumber, time: e.timestamp ? e.timestamp.toISOString() : null, text: eventSummary(view).slice(0, 2000) });
      }
    }
  }

  results() { return this.hits; }
}

const SEVERITY: Record<string, string> = { informational: "info", low: "low", medium: "medium", high: "high", critical: "critical" };

/**
 * Replaces the upload's Sigma findings with the scanner's hits. Returns the
 * findings created (for critical-finding alerts).
 */
export async function saveSigmaFindings(uploadId: string, scanner: SigmaScanner, rules: Map<string, RuleInfo>) {
  // A re-scan replaces the upload's earlier Sigma findings: take their hits
  // back off the rules' totals first so they aren't counted twice.
  const previous = await prisma.logFinding.findMany({ where: { uploadId, sigmaRuleId: { not: null } }, select: { sigmaRuleId: true, eventCount: true } });
  for (const p of previous) {
    await prisma.sigmaRule.updateMany({ where: { id: p.sigmaRuleId!, hitCount: { gte: p.eventCount } }, data: { hitCount: { decrement: p.eventCount } } });
  }
  await prisma.logFinding.deleteMany({ where: { uploadId, sigmaRuleId: { not: null } } });
  const created: { title: string; severity: string }[] = [];
  for (const [ruleId, h] of scanner.results()) {
    const r = rules.get(ruleId);
    if (!r) continue;
    const severity = SEVERITY[r.level] ?? "medium";
    await prisma.logFinding.create({
      data: {
        uploadId,
        sigmaRuleId: r.id,
        title: r.title,
        description: r.description ?? undefined,
        severity,
        eventCount: h.count,
        firstSeen: h.first ?? undefined,
        lastSeen: h.last ?? undefined,
        matchedField: "sigma",
        matchedValue: h.samples[0]?.text,
        details: {
          source: "sigma",
          sigmaId: r.sigmaId, level: r.level, status: r.status, tags: r.tags, references: r.references,
          falsePositives: r.falsePositives, logsource: { product: r.product, category: r.category, service: r.service },
          samples: h.samples,
        },
      },
    });
    await prisma.sigmaRule.update({ where: { id: r.id }, data: { hitCount: { increment: h.count } } });
    created.push({ title: `Sigma: ${r.title}`, severity });
  }
  return created;
}

/** Re-scans an upload's stored events (after a rule update, or for uploads made before Sigma existed). */
export async function scanLogUploadWithSigma(uploadId: string): Promise<{ scanned: number; findings: number; rules: number }> {
  const loaded = await loadSigmaIndex();
  if (!loaded) return { scanned: 0, findings: 0, rules: 0 };
  const scanner = new SigmaScanner(loaded.index);
  let cursor: string | undefined;
  for (;;) {
    const batch = await prisma.logEvent.findMany({
      where: { uploadId },
      select: { id: true, lineNumber: true, timestamp: true, raw: true, normalized: true },
      orderBy: { id: "asc" },
      take: 2000,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    if (batch.length === 0) break;
    for (const e of batch) scanner.add(e);
    cursor = batch[batch.length - 1].id;
  }
  const created = await saveSigmaFindings(uploadId, scanner, loaded.rules);
  const findingCount = await prisma.logFinding.count({ where: { uploadId } });
  await prisma.logUpload.update({ where: { id: uploadId }, data: { findingCount } });
  return { scanned: scanner.scanned, findings: created.length, rules: loaded.index.size };
}
