export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError, isInstanceAdminActor } from "@/lib/auth/api-guard";
import { seedBuiltinPlaybooks } from "@/lib/playbooks/seed";
import { instanceAdminRequired } from "@/lib/auth/org-access";

// POST /api/playbooks/seed — seed (or re-seed) the bundled starter playbooks.
export async function POST(req: NextRequest) {
  try {
    const actor = await getActorOrThrow(req);
    // Built-in playbooks are shared by every organization on the instance.
    if (!isInstanceAdminActor(actor)) return instanceAdminRequired();

    const result = await seedBuiltinPlaybooks();

    return NextResponse.json({
      success: true,
      seeded: result.seeded,
      errors: result.errors,
    });
  } catch (err) {
    if (err instanceof AuthError) return err.toResponse();
    return NextResponse.json({ error: "server_error", detail: String(err) }, { status: 500 });
  }
}
