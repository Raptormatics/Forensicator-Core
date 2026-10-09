/**
 * Shared actor resolution for API routes.
 *
 * Resolves from:
 *   1. Bearer API key (Authorization: Bearer fk_...)
 *   2. NextAuth JWT session cookie
 *
 * Throws a NextResponse(401) if neither is present/valid.
 * Callers should wrap in try/catch and return the thrown NextResponse.
 */
import type { NextRequest } from "next/server";
import { getActorOrThrow, type AuthActor } from "@/lib/auth/api-guard";

export async function getActor(request: NextRequest): Promise<AuthActor> {
  return getActorOrThrow(request);
}
