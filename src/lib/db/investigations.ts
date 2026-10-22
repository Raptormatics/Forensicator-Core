import { cache } from "react";
import { prisma } from "./prisma";
import { notArchived } from "@/lib/cases/archive";

type InvestigationWhere = {
  organizationId?: { in: string[] } | string;
};

// Archived investigations (or ones in an archived case) are listed on the
// Archive page instead.
export async function getInvestigations(where: InvestigationWhere = {}) {
  return prisma.investigation.findMany({
    where: { AND: [where, notArchived()] },
    select: {
      id: true,
      title: true,
      hostname: true,
      username: true,
      status: true,
      findingCount: true,
      tags: true,
      osInfo: true,
      detectionStats: true,
      createdAt: true,
      organizationId: true,
      uploadedBy: {
        select: { email: true, name: true },
      },
      _count: {
        select: { findings: true },
      },
    },
    orderBy: { createdAt: "desc" },
  });
}

export const getInvestigation = cache(async (id: string) =>
  prisma.investigation.findUnique({
    where: { id },
    include: {
      uploadedBy: {
        select: { email: true, name: true }
      },
      case: {
        select: { id: true, caseSeq: true, title: true, status: true, archivedAt: true }
      },
      findings: {
        orderBy: { createdAt: "asc" }
      }
    }
  })
);
