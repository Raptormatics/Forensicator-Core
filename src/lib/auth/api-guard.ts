/**
 * API authentication guard.
 *
 * Resolves the authenticated user from:
 *   1. Bearer API key   →  Authorization: Bearer fk_...
 *   2. NextAuth JWT session cookie
 *
 * Returns the User row or throws AuthError (callers can check instanceof).
 *
 * Core-only — no license enforcement here at all; Forensicator Core is free
 * and unrestricted. The Enterprise overlay replaces this file with an
 * extended version that adds a license-validity check in requireAuth(). Keep
 * everything else in this file identical to the overlay's version so that
 * isn't the only thing that differs between editions.
 */
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";
import { prisma } from "@/lib/db/prisma";
import bcrypt from "bcryptjs";

export type AuthActor = {
  id:              string;
  email:           string;
  name:            string | null;
  role:            string;
  /** All organization IDs this user is a member of. Empty for platform_admin guests. */
  organizationIds: string[];
};

/** Custom error thrown when authentication fails. */
export class AuthError extends Error {
  constructor(public message: string, public status = 401) {
    super(message);
    this.name = "AuthError";
  }
  toResponse() {
    return NextResponse.json(
      { error: this.message, code: "UNAUTHORIZED" },
      { status: this.status }
    );
  }
}

/**
 * Returns a Prisma `where` fragment that restricts records to the actor's orgs.
 *
 * - platform_admin → no restriction (sees everything)
 * - everyone else  → { organizationId: { in: [...actor.organizationIds] } }
 *                    (empty array → matches nothing → sees nothing)
 *
 * Use as: `prisma.investigation.findMany({ where: { ...orgWhere(actor), ...rest } })`
 */
export function orgWhere(actor: AuthActor): { organizationId?: { in: string[] } } {
  if (actor.role === "platform_admin") return {};
  return { organizationId: { in: actor.organizationIds } };
}

/**
 * Resolve the actor for an API route.
 * Throws AuthError on failure — caller should catch and return .toResponse().
 */
export async function requireAuth(request: NextRequest): Promise<AuthActor> {
  return resolveActor(request);
}

async function resolveActor(request: NextRequest): Promise<AuthActor> {
  // ── 1. Bearer API key ──────────────────────────────────────────────────────
  const authHeader = request.headers.get("authorization") ?? "";
  if (authHeader.startsWith("Bearer ")) {
    const raw = authHeader.slice(7).trim();
    if (raw) {
      const prefix = raw.slice(0, 8);
      const candidates = await prisma.apiKey.findMany({
        where: {
          keyPrefix: prefix,
          active: true,
          OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
        },
        include: {
          user: {
            include: { orgMemberships: { select: { organizationId: true } } },
          },
        },
      });

      for (const key of candidates) {
        const valid = await bcrypt.compare(raw, key.keyHash);
        if (valid) {
          await prisma.apiKey.update({
            where: { id: key.id },
            data: { lastUsedAt: new Date(), usageCount: { increment: 1 } },
          });
          return {
            id:              key.user.id,
            email:           key.user.email,
            name:            key.user.name,
            role:            key.user.role,
            organizationIds: key.user.orgMemberships.map((m) => m.organizationId),
          };
        }
      }
      throw new AuthError("Invalid or revoked API key");
    }
  }

  // ── 2. NextAuth JWT session cookie ────────────────────────────────────────
  const token = await getToken({
    req: request,
    secret: process.env.NEXTAUTH_SECRET,
  });

  if (token?.id) {
    const user = await prisma.user.findUnique({
      where: { id: token.id as string },
      include: { orgMemberships: { select: { organizationId: true } } },
    });
    if (user && user.isActive) {
      return {
        id:              user.id,
        email:           user.email,
        name:            user.name,
        role:            user.role,
        organizationIds: user.orgMemberships.map((m) => m.organizationId),
      };
    }
  }

  throw new AuthError("Unauthorized");
}

/** Convenience: returns actor (throws AuthError on failure). */
export async function getActorOrThrow(request: NextRequest): Promise<AuthActor> {
  return requireAuth(request);
}
