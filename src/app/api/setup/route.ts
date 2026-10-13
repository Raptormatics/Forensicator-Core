export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { prisma } from "@/lib/db/prisma";
import { isSetupComplete } from "@/lib/setup/status";

const bodySchema = z.object({
  name:     z.string().min(1).max(100),
  email:    z.string().email().max(255),
  password: z.string().min(8).max(128),
});

class SetupAlreadyCompleteError extends Error {}

// POST — public, one-time only. Creates the one and only user Core ever
// has (no user exists at all until this succeeds — see
// isSetupComplete()), as a member of the single org first-boot.sh
// already seeded (never a user, by design — see scripts/seed-org.ts).
// There's no `role` to assign — Core has no RBAC at all (an
// Enterprise-only capability); this account has unrestricted access.
export async function POST(req: NextRequest) {
  if (await isSetupComplete()) {
    return NextResponse.json({ error: "Setup has already been completed." }, { status: 409 });
  }

  let body;
  try {
    body = bodySchema.parse(await req.json());
  } catch (e) {
    if (e instanceof z.ZodError) return NextResponse.json({ error: e.errors[0].message }, { status: 400 });
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const passwordHash = await bcrypt.hash(body.password, 12);

  try {
    const user = await prisma.$transaction(async (tx) => {
      // Re-checked inside the transaction — the isSetupComplete() check
      // above is best-effort (and cached), not a lock; this is what
      // actually prevents two concurrent submissions both succeeding.
      const count = await tx.user.count();
      if (count > 0) throw new SetupAlreadyCompleteError();

      const created = await tx.user.create({
        data: {
          name: body.name,
          email: body.email,
          passwordHash,
          isActive: true,
        },
      });

      const org = await tx.organization.findFirst();
      if (!org) {
        throw new Error(
          "No organization found — provision.sh/first-boot.sh should have seeded one before setup was ever reachable."
        );
      }
      await tx.organizationMember.create({
        data: {
          organizationId: org.id,
          userId: created.id,
          joinedAt: new Date(),
        },
      });

      return created;
    });

    return NextResponse.json({ email: user.email }, { status: 201 });
  } catch (e) {
    if (e instanceof SetupAlreadyCompleteError) {
      return NextResponse.json({ error: "Setup has already been completed." }, { status: 409 });
    }
    if (e instanceof Error && e.message.includes("Unique constraint")) {
      return NextResponse.json({ error: "That email is already in use." }, { status: 409 });
    }
    console.error("[setup] failed:", e);
    return NextResponse.json({ error: "Setup failed." }, { status: 500 });
  }
}
