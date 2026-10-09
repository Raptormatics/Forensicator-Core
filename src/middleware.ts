/**
 * Next.js middleware — authentication gate.
 *
 * Public routes:  /login, /setup, /api/auth/*, /api/health, /api/setup
 * API routes:     require JWT session OR Bearer header (key validated in handler)
 * Browser routes: require JWT session → redirect to /login
 *
 * /setup itself is NOT gated on "is setup already complete" here — this
 * runs on the Edge runtime and can't reach Prisma. That check happens in
 * the root layout (a Server Component, full Node runtime), which reads
 * the current pathname back off the x-pathname header set below.
 */
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

const PUBLIC_PATHS = [
  "/login",
  "/setup",
  "/forgot-password",
  "/reset-password",
  "/_next",
  "/favicon",
];

const PUBLIC_API_PREFIXES = [
  "/api/auth",
  "/api/setup",
  // Polled by forensicator-update.sh (root, no session) after restarting
  // services post-install/rollback — must be reachable unauthenticated.
  "/api/health",
];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-pathname", pathname);
  const withPathname = () => NextResponse.next({ request: { headers: requestHeaders } });

  // ── Public static / auth paths ─────────────────────────────────────────────
  if (PUBLIC_PATHS.some(p => pathname.startsWith(p))) {
    return withPathname();
  }

  // ── NextAuth API paths ──────────────────────────────────────────────────────
  if (PUBLIC_API_PREFIXES.some(p => pathname.startsWith(p))) {
    return withPathname();
  }

  // ── Check JWT session ──────────────────────────────────────────────────────
  const token = await getToken({
    req: request,
    secret: process.env.NEXTAUTH_SECRET,
  });

  // ── API routes: allow if JWT OR Bearer header present ─────────────────────
  if (pathname.startsWith("/api/")) {
    const hasBearer = request.headers.get("authorization")?.startsWith("Bearer ");
    if (token || hasBearer) return withPathname();
    return NextResponse.json(
      { error: "Unauthorized", code: "UNAUTHORIZED" },
      { status: 401 }
    );
  }

  // ── Browser routes: require JWT session ───────────────────────────────────
  if (!token) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    url.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(url);
  }

  return withPathname();
}

export const config = {
  matcher: [
    /*
     * Match all paths EXCEPT:
     * - _next/static (static files)
     * - _next/image (image optimisation)
     * - favicon.ico
     */
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
