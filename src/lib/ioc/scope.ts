/**
 * Shared IOC scoping/source-derivation logic, used by both the interactive
 * IOC list (paginated) and the Excel export (unpaginated) routes.
 *
 * IocRecord is a global, org-agnostic dedup table (unique by value) fed by
 * four independent pipelines: Investigation uploads (via Evidence), Log
 * Analysis (LogIoc), PCAP Analysis (PcapIoc), and RAM Analysis (RamIoc) —
 * the latter three all the same shape. None of those carry an orgId/caseId
 * of their own, so scoping and "which module(s) surfaced this value" are
 * both derived by joining through Investigation/LogUpload/PcapUpload/
 * RamUpload, which do.
 */
import { prisma } from "@/lib/db/prisma";
import type { AuthActor } from "@/lib/auth/api-guard";
import { orgWhere } from "@/lib/auth/api-guard";

type EvidenceRow = { ip: string | null; url: string | null; hash: string | null; domain: string | null };
type ValueRow = { value: string };

function mergeSources(
  target: Map<string, Set<string>>,
  evidenceRows: EvidenceRow[],
  logRows: ValueRow[],
  pcapRows: ValueRow[],
  ramRows: ValueRow[],
) {
  const add = (value: string | null | undefined, label: string) => {
    if (!value) return;
    if (!target.has(value)) target.set(value, new Set());
    target.get(value)!.add(label);
  };
  for (const r of evidenceRows) {
    add(r.ip, "Investigation");
    add(r.url, "Investigation");
    add(r.hash, "Investigation");
    add(r.domain, "Investigation");
  }
  for (const r of logRows) add(r.value, "Log Analysis");
  for (const r of pcapRows) add(r.value, "PCAP Analysis");
  for (const r of ramRows) add(r.value, "RAM Analysis");
}

/**
 * Resolves the org/case-scoped set of IOC values (for non-admins, or any
 * caseId filter) by walking every module. Returns undefined `valueFilter`
 * when nothing needs scoping (platform admin, no case filter) — callers
 * should then resolve sources for just the values they actually return via
 * `sourcesForValues` below, which is cheaper than a full org-wide join.
 */
export async function deriveScopedIocSources(actor: AuthActor, caseId?: string) {
  const scope = orgWhere(actor);
  const needsScoping = actor.role !== "platform_admin" || !!caseId;
  if (!needsScoping) return { valueFilter: undefined, sources: new Map<string, Set<string>>(), needsScoping };

  const commonWhere = {
    ...(actor.role !== "platform_admin" ? scope : {}),
    ...(caseId ? { caseId } : {}),
  };

  const [investigations, logUploads, pcapUploads, ramUploads] = await Promise.all([
    prisma.investigation.findMany({ where: commonWhere, select: { id: true } }),
    prisma.logUpload.findMany({ where: commonWhere, select: { id: true } }),
    prisma.pcapUpload.findMany({ where: commonWhere, select: { id: true } }),
    prisma.ramUpload.findMany({ where: commonWhere, select: { id: true } }),
  ]);
  const investigationIds = investigations.map((i) => i.id);
  const logUploadIds     = logUploads.map((u) => u.id);
  const pcapUploadIds    = pcapUploads.map((u) => u.id);
  const ramUploadIds     = ramUploads.map((u) => u.id);

  const [evidenceRows, logIocRows, pcapIocRows, ramIocRows] = await Promise.all([
    investigationIds.length
      ? prisma.evidence.findMany({
          where: {
            investigationId: { in: investigationIds },
            OR: [{ ip: { not: null } }, { url: { not: null } }, { hash: { not: null } }, { domain: { not: null } }],
          },
          select: { ip: true, url: true, hash: true, domain: true },
        })
      : [],
    logUploadIds.length
      ? prisma.logIoc.findMany({ where: { uploadId: { in: logUploadIds } }, select: { value: true } })
      : [],
    pcapUploadIds.length
      ? prisma.pcapIoc.findMany({ where: { uploadId: { in: pcapUploadIds } }, select: { value: true } })
      : [],
    ramUploadIds.length
      ? prisma.ramIoc.findMany({ where: { uploadId: { in: ramUploadIds } }, select: { value: true } })
      : [],
  ]);

  const sources = new Map<string, Set<string>>();
  mergeSources(sources, evidenceRows, logIocRows, pcapIocRows, ramIocRows);

  const valueFilter = sources.size > 0 ? { in: Array.from(sources.keys()) } : { in: [] };
  return { valueFilter, sources, needsScoping };
}

/** Resolves source labels for an already-known set of values (unscoped path). */
export async function sourcesForValues(values: string[]): Promise<Map<string, Set<string>>> {
  const sources = new Map<string, Set<string>>();
  if (values.length === 0) return sources;
  const [evidenceRows, logIocRows, pcapIocRows, ramIocRows] = await Promise.all([
    prisma.evidence.findMany({
      where: { OR: [{ ip: { in: values } }, { url: { in: values } }, { hash: { in: values } }, { domain: { in: values } }] },
      select: { ip: true, url: true, hash: true, domain: true },
    }),
    prisma.logIoc.findMany({ where: { value: { in: values } }, select: { value: true } }),
    prisma.pcapIoc.findMany({ where: { value: { in: values } }, select: { value: true } }),
    prisma.ramIoc.findMany({ where: { value: { in: values } }, select: { value: true } }),
  ]);
  mergeSources(sources, evidenceRows, logIocRows, pcapIocRows, ramIocRows);
  return sources;
}

/** A record with no pipeline hit but at least one enrichment only exists
 * because an analyst looked it up manually (POST /api/ioc/enrich). */
export function labelSources(sources: Set<string> | undefined, enrichmentCount: number): string[] {
  if (sources && sources.size > 0) return Array.from(sources);
  return enrichmentCount > 0 ? ["Threat Intel"] : [];
}
