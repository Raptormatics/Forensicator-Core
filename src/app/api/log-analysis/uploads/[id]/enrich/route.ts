/**
 * POST /api/log-analysis/uploads/[id]/enrich — manual re-enrich of every
 * threat-intel-eligible LogIoc value for this upload. See
 * src/lib/intelligence/upload-ioc-enrich.ts for why this is useful beyond
 * the automatic pass the upload processor already runs.
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { enrichUploadIocs, type EnrichableIoc } from "@/lib/intelligence/upload-ioc-enrich";

type Params = { params: Promise<{ id: string }> };

// Mirrors GLOBAL_IOC_TYPE in src/lib/log-analysis/processor.ts — LogIoc's
// type vocabulary is wider than IocRecord's (username/process/filepath have
// no threat-intel meaning and are never enrichable).
const GLOBAL_IOC_TYPE: Record<string, EnrichableIoc["type"] | undefined> = {
  ip: "ip",
  domain: "domain",
  url: "url",
  hash_md5: "hash",
  hash_sha1: "hash",
  hash_sha256: "hash",
  email: "email",
};

export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    const actor = await requireAuth(req);

    const upload = await prisma.logUpload.findUnique({
      where: { id: params.id },
      select: { id: true, organizationId: true },
    });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    const iocs = await prisma.logIoc.findMany({
      where: { uploadId: params.id },
      select: { type: true, value: true },
    });

    const values: EnrichableIoc[] = [];
    for (const ioc of iocs) {
      const type = GLOBAL_IOC_TYPE[ioc.type];
      if (type) values.push({ value: ioc.value, type });
    }

    const result = await enrichUploadIocs(values, upload.organizationId ?? actor.organizationIds[0]);
    return NextResponse.json(result);
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
