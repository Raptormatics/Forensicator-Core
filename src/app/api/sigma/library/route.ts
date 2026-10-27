export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError, isInstanceAdminActor } from "@/lib/auth/api-guard";
import { instanceAdminRequired } from "@/lib/auth/org-access";
import { SIGMA_PACKAGES, getSigmaLibraryState, isSigmaPackage, syncSigmaRules } from "@/lib/sigma/sync";

/** GET /api/sigma/library — the SigmaHQ package in use, when it was synced, and rule counts. */
export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const [state, enabled, running] = await Promise.all([
    getSigmaLibraryState(),
    prisma.sigmaRule.count({ where: { enabled: false } }),
    prisma.sigmaRule.count({ where: { enabled: true, supported: true, covered: true } }),
  ]);
  return NextResponse.json({
    ...state,
    disabledCount: enabled,
    activeCount: running,
    packages: Object.entries(SIGMA_PACKAGES).map(([id, p]) => ({ id, label: p.label, description: p.description })),
  });
}

/** POST /api/sigma/library — download the latest SigmaHQ release of a package ({ package? }) and update the library. */
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }
  // The rule library is shared by the whole instance.
  if (!isInstanceAdminActor(actor)) return instanceAdminRequired();

  const body = (await req.json().catch(() => ({}))) as { package?: string };
  if (body.package !== undefined && !isSigmaPackage(body.package)) {
    return NextResponse.json({ error: "invalid_package", message: `Unknown package: ${body.package}` }, { status: 400 });
  }
  try {
    const result = await syncSigmaRules(body.package as Parameters<typeof syncSigmaRules>[0]);
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json({ error: "sync_failed", message: err instanceof Error ? err.message : "Unknown error" }, { status: 502 });
  }
}
