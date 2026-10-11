export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { execFile } from "child_process";
import { promisify } from "util";
import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { getTsharkPath } from "@/lib/settings/system";

const execFileAsync = promisify(execFile);

// GET — any authenticated user, read-only, no admin gate (same tier as the
// general settings GET — this is purely informational, not a secret).
// tshark has no install/start/stop lifecycle to manage — it's a stateless
// CLI reading a file, so this just confirms the configured binary is
// present and invokable by the app's own service account.
export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const tsharkPath = await getTsharkPath();

  try {
    const { stdout } = await execFileAsync(tsharkPath, ["-v"], { timeout: 5_000 });
    return NextResponse.json({
      available: true,
      path: tsharkPath,
      version: stdout.split("\n")[0]?.trim() ?? null,
    });
  } catch {
    return NextResponse.json({ available: false, path: tsharkPath, version: null });
  }
}
