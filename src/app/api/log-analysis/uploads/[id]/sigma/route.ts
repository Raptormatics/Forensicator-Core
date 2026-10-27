export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { actorOr401, guardOrgAccess } from "@/lib/auth/org-access";
import { scanLogUploadWithSigma } from "@/lib/sigma/scan";

type Params = { params: Promise<{ id: string }> };

/** POST /api/log-analysis/uploads/[id]/sigma — re-run the Sigma rule library over an upload's events. */
export async function POST(req: NextRequest, props: Params) {
  const { id } = await props.params;
  const actor = await actorOr401(req);
  if (actor instanceof NextResponse) return actor;
  const denied = await guardOrgAccess(actor, { logUploadId: id });
  if (denied) return denied;

  const upload = await prisma.logUpload.findUnique({ where: { id }, select: { status: true } });
  if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });
  if (upload.status !== "ready") return NextResponse.json({ error: "not_ready", message: "The upload is still being processed." }, { status: 409 });
  try {
    const result = await scanLogUploadWithSigma(id);
    if (result.rules === 0) return NextResponse.json({ ...result, message: "No Sigma rules are active — update the rule library in Settings → Threat Intelligence." });
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json({ error: "scan_failed", message: err instanceof Error ? err.message : String(err) }, { status: 500 });
  }
}
