import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { actorOr401, guardOrgAccess } from "@/lib/auth/org-access";

export async function GET(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  const actor = await actorOr401(req);
  if (actor instanceof NextResponse) return actor;
  const denied = await guardOrgAccess(actor, { evidenceId: params.id });
  if (denied) return denied;
  const evidence = await prisma.evidence.findUnique({
    where: { id: params.id },
    include: {
      investigation: {
        select: { id: true, title: true, hostname: true }
      },
      finding: {
        select: {
          id: true,
          findingId: true,
          findingType: true,
          category: true,
          severity: true,
          riskScore: true,
          sourceCategory: true,
        }
      },
    },
  });

  if (!evidence) {
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  }

  // Related evidence: same type within same investigation (prev/next by timestamp).
  const [prevEvidence, nextEvidence] = await Promise.all([
    prisma.evidence.findFirst({
      where: {
        investigationId: evidence.investigationId,
        findingId: evidence.findingId,
        timestamp: evidence.timestamp ? { lt: evidence.timestamp } : undefined,
        id: { not: evidence.id },
      },
      orderBy: { timestamp: "desc" },
      select: { id: true, timestamp: true, processName: true, url: true, ip: true, type: true },
    }),
    prisma.evidence.findFirst({
      where: {
        investigationId: evidence.investigationId,
        findingId: evidence.findingId,
        timestamp: evidence.timestamp ? { gt: evidence.timestamp } : undefined,
        id: { not: evidence.id },
      },
      orderBy: { timestamp: "asc" },
      select: { id: true, timestamp: true, processName: true, url: true, ip: true, type: true },
    }),
  ]);

  return NextResponse.json({ evidence, prevEvidence, nextEvidence });
}
