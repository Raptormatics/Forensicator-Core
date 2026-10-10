export const runtime = "nodejs";
import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { prisma } from "@/lib/db/prisma";

// POST /api/auth/logout — writes the audit trail for a sign-out.
//
// NextAuth's signOut() (called from the sidebar) only ever clears the JWT
// cookie client-side; authOptions (src/auth.config.ts) defines no `events`
// object, so nothing server-side fires on logout at all today, and under
// the JWT session strategy this app uses, NextAuth v4's events.signOut is
// known to be unreliable regardless. A dedicated route the client hits
// while the session is still valid — right before calling signOut() — is
// the reliable way to log this, rather than depending on a hook that may
// not fire. Doesn't itself end the session; that's still signOut()'s job.
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const actorIp = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? req.headers.get("x-real-ip") ?? null;

  await prisma.auditLog.create({
    data: {
      actorId: actor.id,
      actorEmail: actor.email,
      actorIp,
      action: "logout",
      resourceType: "user",
      resourceId: actor.id,
      result: "success",
      severity: "info",
    },
  });

  return NextResponse.json({ ok: true });
}
