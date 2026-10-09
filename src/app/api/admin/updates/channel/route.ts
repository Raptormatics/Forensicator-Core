export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { isInstanceAdmin } from "@/lib/auth/session";
import { CHANNELS, getChannel, setChannel } from "@/lib/updates/online";

// GET — platform_admin, or org_admin in appliance mode (see
// isInstanceAdmin). Current update channel selection.
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  return NextResponse.json({ channel: getChannel(), channels: CHANNELS });
}

const bodySchema = z.object({ channel: z.enum(CHANNELS) });

// PUT — platform_admin, or org_admin in appliance mode (see isInstanceAdmin).
export async function PUT(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  if (!isInstanceAdmin(actor.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const { channel } = bodySchema.parse(await req.json());
  setChannel(channel);
  return NextResponse.json({ channel });
}
