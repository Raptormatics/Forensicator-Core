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
 * and unrestricted. Core is also single-user/single-org: there is no `role`
 * field on AuthActor at all here (RBAC — the User.role/OrganizationMember.role
 * columns, multi-user creation, and every role-based check — is an
 * Enterprise-only capability; that code doesn't exist in Core, not just a
 * gated version of it). The Enterprise overlay replaces this file with an
 * extended version that restores `role`, adds a license-validity check in
 * requireAuth(), and makes orgWhere() genuinely role-aware again.
 */
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";
import { prisma } from "@/lib/db/prisma";
import bcrypt from "bcryptjs";
import { getServerSession } from "@/lib/auth/session";

export type AuthActor = {
  id:              string;
  email:           string;
  name:            string | null;
  /** All organization IDs this user is a member of. Core has exactly one. */
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
 * Returns a Prisma `where` fragment that restricts records to the actor's
 * orgs. Core is permanently single-user/single-org, so this is always a
 * no-op — unconditionally no restriction, same shape as every other
 * edition so the ~25 call sites that splat this into a Prisma `where`
 * clause (investigations/cases/hosts/reports/etc.) never needed to know
 * the actual rule changed. The Enterprise overlay replaces this file with
 * a version that restricts non-platform_admin, non-appliance-org_admin
 * actors to their own orgs.
 *
 * Use as: `prisma.investigation.findMany({ where: { ...orgWhere(actor), ...rest } })`
 */
export function orgWhere(_actor: AuthActor): { organizationId?: { in: string[] } } {
  return {};
}

/**
 * The organizations an actor may access, or null for unrestricted.
 * orgWhere() (lists) and guardOrgAccess() in org-access.ts (single
 * records by id) both follow it. Core is single-org, so always
 * unrestricted; the Enterprise overlay has its own version.
 */
export function orgAccessScope(_actor: AuthActor): string[] | null {
  return null;
}

/**
 * Instance-wide administration — system settings, AI configuration,
 * updates, license, built-in content seeding. Core's sole user always
 * qualifies; the Enterprise overlay limits it by role.
 */
export function isInstanceAdminActor(_actor: AuthActor): boolean {
  return true;
}

/** The signed-in user for a server-rendered page, or null if signed out. */
export async function getPageActor(): Promise<AuthActor | null> {
  const session = await getServerSession();
  const id = (session?.user as { id?: string } | undefined)?.id;
  if (!id) return null;
  const user = await prisma.user.findUnique({
    where: { id },
    include: { orgMemberships: { select: { organizationId: true } } },
  });
  if (!user || !user.isActive) return null;
  return { id: user.id, email: user.email, name: user.name, organizationIds: user.orgMemberships.map((m) => m.organizationId) };
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
