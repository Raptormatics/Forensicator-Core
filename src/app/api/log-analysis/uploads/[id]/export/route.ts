/**
 * GET /api/log-analysis/uploads/[id]/export — this upload's extracted IOCs
 * as a single-sheet Excel workbook.
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { buildXlsxBuffer } from "@/lib/reports/xlsx-export";
import { actorOr401, guardOrgAccess } from "@/lib/auth/org-access";

type Params = { params: Promise<{ id: string }> };

export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  const orgActor = await actorOr401(req);
  if (orgActor instanceof NextResponse) return orgActor;
  const orgDenied = await guardOrgAccess(orgActor, { logUploadId: params.id });
  if (orgDenied) return orgDenied;
  try {
    await requireAuth(req);
    const { id } = params;

    const upload = await prisma.logUpload.findUnique({ where: { id }, select: { id: true, filename: true } });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    const iocs = await prisma.logIoc.findMany({ where: { uploadId: id }, orderBy: [{ count: "desc" }] });

    const buffer = await buildXlsxBuffer([
      {
        name: "IOCs",
        columns: [
          { header: "Type", key: "type", width: 14 },
          { header: "Value", key: "value", width: 45 },
          { header: "Count", key: "count", width: 10 },
        ],
        rows: iocs.map((i) => ({ type: i.type, value: i.value, count: i.count })),
      },
    ]);

    const filename = `log-analysis-iocs-${upload.filename.replace(/[^a-zA-Z0-9._-]/g, "_")}.xlsx`;
    return new NextResponse(new Uint8Array(buffer), {
      headers: {
        "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Content-Length": String(buffer.length),
      },
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
