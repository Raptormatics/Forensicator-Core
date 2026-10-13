/**
 * Server-side session helpers.
 * Use getServerSession() inside Server Components and API routes.
 *
 * Core is single-user/single-org — there's no `role` concept at all here
 * (RBAC is an Enterprise-only capability, not a gated version of working
 * code; see src/lib/auth/api-guard.ts's AuthActor). The sole account
 * created at setup has unrestricted access to everything, so there's
 * nothing for ADMIN_ROLES/isAdmin()/isInstanceAdmin() to gate — every call
 * site that used to check them in Core just does the admin thing
 * unconditionally now. The Enterprise overlay replaces this file with a
 * version that restores all three.
 */
import { getServerSession as _getServerSession } from "next-auth";
import { authOptions } from "@/auth.config";
import type { Session } from "next-auth";

export type AppSession = Session & {
  user: { id: string; email: string; name: string };
};

export function getServerSession(): Promise<AppSession | null> {
  return _getServerSession(authOptions) as Promise<AppSession | null>;
}
