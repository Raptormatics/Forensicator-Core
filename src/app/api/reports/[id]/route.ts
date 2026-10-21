/**
 * GET  /api/reports/[id]        — report status
 * DELETE /api/reports/[id]      — delete report + file
 */
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import { prisma } from "@/lib/db/prisma";
import { guardCaseOpen } from "@/lib/cases/case-lock";

export const runtime = "nodejs";

export async function GET(_req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  const report = await prisma.report.findUnique({
    where: { id: params.id },
    select: {
      id: true, status: true, type: true, format: true,
      fileSize: true, errorMessage: true, createdAt: true, updatedAt: true,
      investigationId: true,
      generatedBy: { select: { id: true, name: true, email: true } },
    },
  });
  if (!report) return NextResponse.json({ error: "not_found" }, { status: 404 });
  return NextResponse.json({ report });
}

export async function DELETE(_req: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  const report = await prisma.report.findUnique({ where: { id: params.id } });
  if (!report) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const locked = await guardCaseOpen({ reportId: report.id }, "deleting its reports");
  if (locked) return locked;

  if (report.filePath && fs.existsSync(report.filePath)) {
    try { fs.unlinkSync(report.filePath); } catch { /* ignore */ }
  }
  await prisma.report.delete({ where: { id: params.id } });
  return NextResponse.json({ deleted: true });
}
