/**
 * ZIP bundle export — packages the case JSON + case-wide evidence CSV together.
 */
import AdmZip from "adm-zip";
import { prisma } from "@/lib/db/prisma";
import { generateCaseJson } from "./json-export";
import { generateEvidenceCsv } from "./csv-export";

export async function generateCaseZip(caseId: string): Promise<Buffer> {
  const caseInvs = await prisma.investigation.findMany({
    where: { caseId },
    select: { id: true },
  });
  const investigationIds = caseInvs.map((ci) => ci.id);

  const [jsonStr, evidenceRows] = await Promise.all([
    generateCaseJson(caseId),
    investigationIds.length > 0
      ? prisma.evidence.findMany({
          where: { investigationId: { in: investigationIds } },
          include: {
            finding: {
              select: { findingId: true, findingType: true, category: true, severity: true },
            },
          },
          orderBy: { createdAt: "asc" },
        })
      : Promise.resolve([]),
  ]);

  const csvStr = generateEvidenceCsv(evidenceRows);

  const zip = new AdmZip();
  zip.addFile("case.json", Buffer.from(jsonStr, "utf8"));
  zip.addFile("evidence.csv", Buffer.from(csvStr, "utf8"));
  return zip.toBuffer();
}
