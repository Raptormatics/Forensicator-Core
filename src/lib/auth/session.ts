/**
 * Server-side session helpers.
 * Use getServerSession() inside Server Components and API routes.
 */
import { getServerSession as _getServerSession } from "next-auth";
import { authOptions } from "@/auth.config";
import type { Session } from "next-auth";
import { isAppliance } from "@/lib/config/deployment";

export type AppSession = Session & {
  user: { id: string; email: string; name: string; role: string };
};

export function getServerSession(): Promise<AppSession | null> {
  return _getServerSession(authOptions) as Promise<AppSession | null>;
}

/** Roles that grant admin-level access */
export const ADMIN_ROLES = ["platform_admin", "org_admin"] as const;

export function isAdmin(role: string) {
  return ADMIN_ROLES.includes(role as (typeof ADMIN_ROLES)[number]);
}

/**
 * Instance-wide administration — platform updates, system settings:
 * anything that affects the whole shared platform in SaaS mode (every
 * org), so it stays platform_admin-only there. Appliance mode never
 * seeds a platform_admin — only ever org_admin, the sole tenant's own
 * admin — so org_admin manages their own instance's version of this too.
 */
export function isInstanceAdmin(role: string): boolean {
  if (role === "platform_admin") return true;
  return role === "org_admin" && isAppliance();
}
