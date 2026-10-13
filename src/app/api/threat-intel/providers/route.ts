export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import {
  ALL_PROVIDER_NAMES,
  isKeyedProvider,
  listOrgProviderStatus,
  setOrgProviderKey,
  setOrgProviderEnabled,
  clearOrgProviderOverride,
} from "@/lib/intelligence/org-providers";
import { z } from "zod";

const PROVIDER_ENUM = z.enum(ALL_PROVIDER_NAMES as [string, ...string[]]);

// GET — any authenticated org member can view (masked) provider status, for all providers.
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const orgId = actor.organizationIds[0];
  if (!orgId) return NextResponse.json({ error: "No organization associated with your account" }, { status: 400 });

  const providers = await listOrgProviderStatus(orgId);
  return NextResponse.json({ providers });
}

const putSchema = z.object({
  provider: PROVIDER_ENUM,
  apiKey: z.string().min(1).max(500).optional(),
  enabled: z.boolean().optional(),
});

// PUT — unrestricted (Core's sole user). Set/replace a key (keyed providers only), and/or toggle enabled (any provider).
export async function PUT(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const orgId = actor.organizationIds[0];
  if (!orgId) return NextResponse.json({ error: "No organization associated with your account" }, { status: 400 });

  const body = putSchema.parse(await req.json());

  if (body.apiKey) {
    if (!isKeyedProvider(body.provider)) {
      return NextResponse.json({ error: "This provider does not use an API key" }, { status: 400 });
    }
    await setOrgProviderKey(orgId, body.provider, body.apiKey, body.enabled ?? true);
  } else if (body.enabled !== undefined) {
    await setOrgProviderEnabled(orgId, body.provider, body.enabled);
  } else {
    return NextResponse.json({ error: "Provide apiKey and/or enabled" }, { status: 400 });
  }

  const providers = await listOrgProviderStatus(orgId);
  return NextResponse.json({ providers });
}

const deleteSchema = z.object({ provider: PROVIDER_ENUM });

// DELETE — unrestricted (Core's sole user). Clear the org's override (key and/or toggle), reverting to defaults.
export async function DELETE(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const orgId = actor.organizationIds[0];
  if (!orgId) return NextResponse.json({ error: "No organization associated with your account" }, { status: 400 });

  const provider = deleteSchema.parse({ provider: req.nextUrl.searchParams.get("provider") }).provider;
  await clearOrgProviderOverride(orgId, provider);

  const providers = await listOrgProviderStatus(orgId);
  return NextResponse.json({ providers });
}
