/**
 * GET /api/reports/[id]/download — stream the generated file to the client.
 */
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { prisma } from "@/lib/db/prisma";
import { formatCaseNumber } from "@/lib/cases/case-number";
import { actorOr401, guardOrgAccess } from "@/lib/auth/org-access";

export const runtime = "nodejs";

const MIME: Record<string, string> = {
  pdf:  "application/pdf",
  csv:  "text/csv",
  json: "application/json",
  zip:  "application/zip",
};

export async function GET(req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  const orgActor = await actorOr401(req);
  if (orgActor instanceof NextResponse) return orgActor;
  const orgDenied = await guardOrgAccess(orgActor, { reportId: params.id });
  if (orgDenied) return orgDenied;
  const report = await prisma.report.findUnique({
    where: { id: params.id },
    include: { case: { select: { caseSeq: true } } },
  });
  if (!report) return NextResponse.json({ error: "not_found" }, { status: 404 });
  if (report.status !== "ready" || !report.filePath) {
    return NextResponse.json({ error: "not_ready", status: report.status }, { status: 409 });
  }
  if (!fs.existsSync(report.filePath)) {
    return NextResponse.json({ error: "file_missing" }, { status: 410 });
  }

  const fileBuffer = fs.readFileSync(report.filePath);
  const mime = MIME[report.format] ?? "application/octet-stream";
  const ext  = report.format;
  const ref = report.case
    ? formatCaseNumber(report.case.caseSeq)
    : report.investigationId?.slice(0, 8) ?? report.id.slice(0, 8);
  const filename = `forensicator-${report.type}-${ref}.${ext}`;

  return new NextResponse(fileBuffer, {
    headers: {
      "Content-Type": mime,
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Content-Length": String(fileBuffer.length),
    },
  });
}
