export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { CHANNELS, getChannel, setChannel } from "@/lib/updates/online";

// GET — unrestricted (Core's sole user). Current update channel selection.
export async function GET(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }


  return NextResponse.json({ channel: getChannel(), channels: CHANNELS });
}

const bodySchema = z.object({ channel: z.enum(CHANNELS) });

// PUT — unrestricted (Core's sole user).
export async function PUT(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }


  const { channel } = bodySchema.parse(await req.json());
  setChannel(channel);
  return NextResponse.json({ channel });
}
