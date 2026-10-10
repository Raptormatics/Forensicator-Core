/**
 * NextAuth v4 configuration — Credentials provider (email + password).
 * JWT sessions — no extra DB tables required.
 */
import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { prisma } from "@/lib/db/prisma";
import bcrypt from "bcryptjs";

// Extended user type that includes new auth fields
// (Prisma types update after `prisma generate` / server restart)
type AuthUser = {
  id: string; email: string; name: string | null; role: string;
  passwordHash: string | null; isActive: boolean; lastLogin: Date | null;
  failedLoginAttempts: number; lockedUntil: Date | null;
};

// Brute-force lockout: 5 failed attempts locks the account for 15 minutes.
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

function minutesRemaining(lockedUntil: Date): number {
  return Math.max(1, Math.ceil((lockedUntil.getTime() - Date.now()) / 60_000));
}

export const authOptions: NextAuthOptions = {
  session: { strategy: "jwt", maxAge: 8 * 60 * 60 }, // 8-hour sessions
  pages: {
    signIn: "/login",
    error:  "/login",
  },
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email:    { label: "Email",    type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials, req) {
        if (!credentials?.email || !credentials?.password) return null;

        const email = credentials.email.toLowerCase().trim();
        const user = await prisma.user.findUnique({ where: { email } }) as AuthUser | null;

        if (!user || !user.isActive) return null;

        const actorIp =
          (req?.headers?.["x-forwarded-for"] as string | undefined)?.split(",")[0]?.trim() ??
          (req?.headers?.["x-real-ip"] as string | undefined) ??
          null;

        // Already locked from a prior burst of failed attempts.
        if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
          throw new Error(
            `Account locked due to repeated failed sign-in attempts. Try again in ${minutesRemaining(user.lockedUntil)} minute(s).`
          );
        }

        // If no passwordHash set — account not activated yet
        if (!user.passwordHash) return null;

        const valid = await bcrypt.compare(credentials.password, user.passwordHash);

        if (!valid) {
          const attempts = user.failedLoginAttempts + 1;
          const locking = attempts >= MAX_FAILED_ATTEMPTS;
          const lockedUntil = locking ? new Date(Date.now() + LOCKOUT_MINUTES * 60_000) : null;

          await prisma.user.update({
            where: { id: user.id },
            data: { failedLoginAttempts: locking ? 0 : attempts, lockedUntil },
          });

          await prisma.auditLog.create({
            data: {
              actorId: user.id,
              actorEmail: user.email,
              actorIp,
              action: locking ? "login_locked" : "login_failed",
              resourceType: "user",
              resourceId: user.id,
              result: "denied",
              severity: locking ? "critical" : "warning",
              metadata: { attempts } as never,
            },
          });

          if (locking) {
            throw new Error(`Account locked due to repeated failed sign-in attempts. Try again in ${LOCKOUT_MINUTES} minute(s).`);
          }
          return null;
        }

        // Successful login — reset the failure counter and update last login timestamp.
        await prisma.user.update({
          where: { id: user.id },
          data: { lastLogin: new Date(), failedLoginAttempts: 0, lockedUntil: null },
        });

        // No organizationId here, same as the login_failed/login_locked
        // writes above — orgWhere() (src/lib/auth/api-guard.ts) treats
        // org_admin in appliance mode the same as platform_admin for
        // exactly this reason, so it's still visible in the Audit Log.
        await prisma.auditLog.create({
          data: {
            actorId: user.id,
            actorEmail: user.email,
            actorIp,
            action: "login_success",
            resourceType: "user",
            resourceId: user.id,
            result: "success",
            severity: "info",
          },
        });

        return {
          id:             user.id,
          email:          user.email,
          name:           user.name ?? user.email,
          role:           user.role,
        };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id   = user.id;
        token.role = (user as { role?: string }).role ?? "analyst";
      }
      return token;
    },
    async session({ session, token }) {
      if (token && session.user) {
        session.user.id   = token.id as string;
        session.user.role = token.role as string;
      }
      return session;
    },
    // NextAuth's default redirect callback resolves relative URLs against
    // `baseUrl` (== NEXTAUTH_URL) — on an appliance built before its
    // eventual IP is known, that's still the http://localhost:3000
    // provision.sh default unless someone explicitly set PUBLIC_URL, so
    // every relative redirect (e.g. signOut's callbackUrl: "/login")
    // sends the browser to localhost instead of wherever it's actually
    // being accessed from. Returning relative URLs as-is here instead of
    // prefixing baseUrl lets the browser resolve them against its own
    // current origin — same fix either way, whether NEXTAUTH_URL is
    // stale or just doesn't match how a given visitor is reaching this
    // instance (reverse proxy, alternate hostname, etc).
    async redirect({ url, baseUrl }) {
      if (url.startsWith("/")) return url;
      try {
        if (new URL(url).origin === baseUrl) return url;
      } catch {
        // not a valid absolute URL — fall through to baseUrl below
      }
      return baseUrl;
    },
  },
};
