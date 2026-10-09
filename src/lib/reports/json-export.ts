/**
 * JSON export — full structured Case dump: every linked investigation
 * (with its findings) plus, when the Log/PCAP/RAM Analysis overlay is
 * installed, every such upload belonging to the case (with its findings).
 */
import { prisma } from "@/lib/db/prisma";
import { severityRank } from "@/lib/severity";

// A non-literal specifier — unlike an inlined string, this isn't
// statically resolvable, so tsc doesn't try to resolve the module at
// compile time and hard-fail the build when it's absent (Forensicator
// Core, no Enterprise overlay). The dynamic import below still fails at
// runtime the same way either way; only the compile-time check differs.
const MODULE_REPORT_DATA_MODULE = "@/lib/reports/module-report-data";

export async function generateCaseJson(caseId: string): Promise<string> {
  const kase = await prisma.case.findUniqueOrThrow({
    where: { id: caseId },
    include: {
      investigations: {
        include: { findings: true },
      },
    },
  });

  for (const investigation of kase.investigations) {
    investigation.findings.sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.category.localeCompare(b.category)
    );
  }

  // Log/PCAP/RAM Analysis — Enterprise overlay only, not present in
  // Forensicator Core. Degrades to investigations-only when absent.
  let moduleUploads: { logUploads: unknown[]; pcapUploads: unknown[]; ramUploads: unknown[] } = {
    logUploads: [], pcapUploads: [], ramUploads: [],
  };
  try {
    const { getModuleUploadsForJson } = await import(MODULE_REPORT_DATA_MODULE);
    moduleUploads = await getModuleUploadsForJson(caseId);
  } catch (moduleErr) {
    console.warn("[json-export] Log/PCAP/RAM module data skipped:", moduleErr instanceof Error ? moduleErr.message : moduleErr);
  }

  return JSON.stringify({ ...kase, ...moduleUploads }, null, 2);
}
