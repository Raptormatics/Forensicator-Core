export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { getActivationState, activateLicense } from "@/lib/license/activation";
import { InvalidLicenseError } from "@/lib/license/verify";

// GET — platform_admin, or org_admin in appliance mode (see
// isInstanceAdmin). Current Enterprise-overlay entitlement state.
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  return NextResponse.json(getActivationState());
}

const bodySchema = z.object({ licContent: z.string().min(1) });

// POST — platform_admin, or org_admin in appliance mode. Verifies and
// stores a .lic file — this only unlocks downloading/installing the
// Enterprise overlay (see /settings/updates); it does not itself install
// anything.
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  let body;
  try {
    body = bodySchema.parse(await req.json());
  } catch (e) {
    if (e instanceof z.ZodError) return NextResponse.json({ error: e.errors[0].message }, { status: 400 });
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  let state;
  try {
    state = activateLicense(body.licContent);
  } catch (e) {
    const msg = e instanceof InvalidLicenseError ? e.message : "License activation failed.";
    return NextResponse.json({ error: msg }, { status: 400 });
  }

  await prisma.auditLog.create({
    data: {
      actorId: actor.id,
      actorEmail: actor.email,
      action: "enterprise_license_activated",
      resourceType: "system",
      resourceId: state.licenseId,
      result: "success",
      severity: "warning",
      metadata: { licenseType: state.licenseType, plan: state.plan, customerName: state.customerName } as never,
    },
  });

  return NextResponse.json(state);
}
