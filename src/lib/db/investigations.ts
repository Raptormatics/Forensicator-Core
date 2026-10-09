import { cache } from "react";
import { prisma } from "./prisma";

type InvestigationWhere = {
  organizationId?: { in: string[] } | string;
};

export async function getInvestigations(where: InvestigationWhere = {}) {
  return prisma.investigation.findMany({
    where,
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
      findings: {
        orderBy: { createdAt: "asc" }
      }
    }
  })
);
