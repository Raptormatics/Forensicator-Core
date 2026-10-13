export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Core is single-user — the one account created at setup. This route exists
 * only so assignee pickers (cases/[id]/page.tsx, quick-task-modal.tsx,
 * assignee-panel.tsx) have someone to list; there is no user creation,
 * editing, or listing of "other" users here at all. The Enterprise overlay
 * replaces this file with the real multi-user management API.
 */
import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";

export async function GET(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    return NextResponse.json({
      users: [{ id: actor.id, name: actor.name, email: actor.email }],
    });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
