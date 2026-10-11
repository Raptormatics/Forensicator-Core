/**
 * POST /api/ram-analysis/uploads/[id]/enrich — manual re-enrich of every
 * RamIoc value for this upload. See
 * src/lib/intelligence/upload-ioc-enrich.ts for why this is useful beyond
 * the automatic pass the upload processor already runs.
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { enrichUploadIocs, type EnrichableIoc } from "@/lib/intelligence/upload-ioc-enrich";

type Params = { params: Promise<{ id: string }> };

export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    const actor = await requireAuth(req);

    const upload = await prisma.ramUpload.findUnique({
      where: { id: params.id },
      select: { id: true, organizationId: true },
    });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    const iocs = await prisma.ramIoc.findMany({
      where: { uploadId: params.id },
      select: { type: true, value: true },
    });

    // RamIoc's type vocabulary ("ip" | "domain") is already a subset of
    // IocRecord's — no mapping needed, just filter defensively.
    const values: EnrichableIoc[] = iocs
      .filter((i): i is { type: "ip" | "domain"; value: string } => i.type === "ip" || i.type === "domain")
      .map((i) => ({ value: i.value, type: i.type }));

    const result = await enrichUploadIocs(values, upload.organizationId ?? actor.organizationIds[0]);
    return NextResponse.json(result);
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
