/**
 * Report generation worker.
 * Processes jobs from the "forensicator:reports" queue.
 *
 * Reports are generated per-Case, aggregating every investigation linked to
 * the case (always) plus every Log/PCAP/RAM analysis upload belonging to
 * the case, when that overlay is installed (see loadCaseReportData below)
 * into one normalized findings list — see src/lib/reports/types.ts.
 *
 * Generates PDF/CSV/JSON/ZIP files and saves them under the configured
 * reports directory — see src/lib/settings/system.ts's getReportsDir()
 * (Settings -> General override, else REPORTS_DIR env var, else
 * ./reports-output in the project root). Read fresh per job, not cached
 * at module load, so changing it in Settings takes effect immediately —
 * unlike Redis connection info, this isn't tied to any connection pool.
 */
import path from "path";
import fs from "fs";
import { Worker, Job } from "bullmq";
import { getRedisConnection } from "./redis";
import { prisma } from "@/lib/db/prisma";
import type { ReportJobData } from "./queues";
import { getReportsDir } from "@/lib/settings/system";
import { generateExecutivePdf, type ExecutiveReportInput } from "@/lib/reports/pdf-executive";
import { generateTechnicalPdf, type TechnicalReportInput } from "@/lib/reports/pdf-technical";
import { generateEvidenceCsv } from "@/lib/reports/csv-export";
import { generateCaseJson } from "@/lib/reports/json-export";
import { generateCaseZip } from "@/lib/reports/zip-export";
import { severityRank } from "@/lib/severity";
import type { CaseReportFinding, ModuleCounts } from "@/lib/reports/types";

const REPORT_QUEUE = "forensicator-reports";

// A non-literal specifier — unlike an inlined string, this isn't
// statically resolvable, so tsc doesn't try to resolve the module at
// compile time and hard-fail the build when it's absent (Forensicator
// Core, no Enterprise overlay). The dynamic import below still fails at
// runtime the same way either way; only the compile-time check differs.
const MODULE_REPORT_DATA_MODULE = "@/lib/reports/module-report-data";

/** Fetches everything tied to a case and normalizes it into one findings list. */
async function loadCaseReportData(caseId: string) {
  const kase = await prisma.case.findUniqueOrThrow({
    where: { id: caseId },
    include: {
      investigations: {
        include: {
          findings: true,
          evidence: { select: { type: true, ip: true, url: true, hash: true, domain: true }, take: 1000 },
          timelineEvents: { orderBy: { timestamp: "asc" }, take: 200 },
        },
      },
    },
  });

  const investigations = kase.investigations;
  const hosts = Array.from(new Set(investigations.map((i) => i.hostname).filter((h): h is string => !!h)));

  const findings: CaseReportFinding[] = [];
  for (const inv of investigations) {
    for (const f of inv.findings) {
      findings.push({ id: f.id, source: "investigation", title: f.findingType, category: f.category, severity: f.severity, summary: f.aiSummary });
    }
  }

  const moduleCounts: ModuleCounts = {
    investigations: investigations.reduce((sum, i) => sum + i.findings.length, 0),
    log: 0, pcap: 0, ram: 0,
  };

  // Log/PCAP/RAM Analysis — Enterprise overlay only, not present in
  // Forensicator Core. Degrades to investigations-only when absent.
  try {
    const { getModuleReportData } = await import(MODULE_REPORT_DATA_MODULE);
    const moduleData = await getModuleReportData(caseId);
    findings.push(...moduleData.findings);
    Object.assign(moduleCounts, moduleData.moduleCounts);
  } catch (moduleErr) {
    console.warn("[report-worker] Log/PCAP/RAM module data skipped:", moduleErr instanceof Error ? moduleErr.message : moduleErr);
  }

  // Most-severe-first — `severity` is a free-text column ("Important",
  // "Critical", ...), so a plain DB orderBy sorts it alphabetically
  // (Important < Informational < Interesting < Notable), which buried
  // every Notable-tier finding behind Informational noise in the
  // executive report's top-20 table. Rank explicitly instead.
  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  const investigationIds = investigations.map((i) => i.id);
  const evidenceCount = investigationIds.length > 0
    ? await prisma.evidence.count({ where: { investigationId: { in: investigationIds } } })
    : 0;
  const iocCount = investigationIds.length > 0
    ? await prisma.evidence.count({
        where: { investigationId: { in: investigationIds }, OR: [{ ip: { not: null } }, { url: { not: null } }, { hash: { not: null } }, { domain: { not: null } }] },
      })
    : 0;

  const distinctIocs: { type: string; value: string }[] = [];
  for (const inv of investigations) {
    for (const ev of inv.evidence) {
      if (ev.ip)     distinctIocs.push({ type: "ip",     value: ev.ip });
      if (ev.hash)   distinctIocs.push({ type: "hash",   value: ev.hash });
      if (ev.url)    distinctIocs.push({ type: "url",    value: ev.url });
      if (ev.domain) distinctIocs.push({ type: "domain", value: ev.domain });
    }
  }

  const timelineEvents = investigations
    .flatMap((i) => i.timelineEvents)
    .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  return {
    case: {
      id: kase.id, caseSeq: kase.caseSeq, title: kase.title, description: kase.description,
      status: kase.status, severity: kase.severity, tags: kase.tags, createdAt: kase.createdAt,
    },
    hosts,
    investigationCount: investigations.length,
    findings,
    moduleCounts,
    evidenceCount,
    iocCount,
    iocs: distinctIocs.slice(0, 500),
    timelineEvents: timelineEvents.map((t) => ({ timestamp: t.timestamp, title: t.title, category: t.category, severity: t.severity })),
    investigationIds,
  };
}

async function processReport(job: Job<ReportJobData>) {
  const { reportId, caseId, type, format } = job.data;

  await prisma.report.update({ where: { id: reportId }, data: { status: "generating" } });

  const REPORTS_DIR = await getReportsDir();
  fs.mkdirSync(REPORTS_DIR, { recursive: true });

  try {
    let fileBuffer: Buffer;
    let ext: string;

    if (format === "pdf") {
      const data = await loadCaseReportData(caseId);

      if (type === "executive") {
        const input: ExecutiveReportInput = {
          case: data.case,
          hosts: data.hosts,
          investigationCount: data.investigationCount,
          findings: data.findings,
          moduleCounts: data.moduleCounts,
          evidenceCount: data.evidenceCount,
          iocCount: data.iocCount,
        };
        fileBuffer = await generateExecutivePdf(input);
      } else {
        const input: TechnicalReportInput = {
          case: data.case,
          hosts: data.hosts,
          investigationCount: data.investigationCount,
          moduleCounts: data.moduleCounts,
          findings: data.findings,
          iocs: data.iocs,
          timelineEvents: data.timelineEvents,
        };
        fileBuffer = await generateTechnicalPdf(input);
      }
      ext = "pdf";

    } else if (format === "csv") {
      const caseInvs = await prisma.investigation.findMany({ where: { caseId }, select: { id: true } });
      const investigationIds = caseInvs.map((ci) => ci.id);
      const rows = investigationIds.length > 0
        ? await prisma.evidence.findMany({
            where: { investigationId: { in: investigationIds } },
            include: { finding: { select: { findingId: true, findingType: true, category: true, severity: true } } },
            orderBy: { createdAt: "asc" },
          })
        : [];
      fileBuffer = Buffer.from(generateEvidenceCsv(rows), "utf8");
      ext = "csv";

    } else if (format === "json") {
      const jsonStr = await generateCaseJson(caseId);
      fileBuffer = Buffer.from(jsonStr, "utf8");
      ext = "json";

    } else {
      fileBuffer = await generateCaseZip(caseId);
      ext = "zip";
    }

    const fileName  = `${reportId}.${ext}`;
    const filePath  = path.join(REPORTS_DIR, fileName);
    fs.writeFileSync(filePath, fileBuffer);

    await prisma.report.update({
      where: { id: reportId },
      data: {
        status:       "ready",
        filePath:     filePath,
        fileSize:     fileBuffer.length,
        // Clear any error left over from an earlier failed attempt on this
        // same job (BullMQ retries in place) — otherwise a report that
        // succeeded on retry still displays its first attempt's error.
        errorMessage: null,
      },
    });

    console.log(`[report-worker] report ${reportId} ready — ${fileBuffer.length} bytes`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[report-worker] report ${reportId} failed:`, msg);
    await prisma.report.update({
      where: { id: reportId },
      data: { status: "failed", errorMessage: msg },
    });
    throw err; // BullMQ will retry based on job options
  }
}

export function startReportWorker() {
  const worker = new Worker<ReportJobData>(REPORT_QUEUE, processReport, {
    connection: getRedisConnection(),
    concurrency: 2,
  });
  worker.on("error", (err) => console.error("[report-worker]", err));
  return worker;
}
