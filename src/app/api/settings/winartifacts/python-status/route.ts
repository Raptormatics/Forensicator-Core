export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { execFile } from "child_process";
import { promisify } from "util";
import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { getWinArtifactsPythonPath } from "@/lib/settings/system";

const execFileAsync = promisify(execFile);

// GET — any authenticated user, read-only, no admin gate (same tier as the
// tshark-status/volatility-status routes). Checks both the interpreter
// itself and that regipy actually imports, since a venv can exist without
// its packages installed.
export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const pythonPath = await getWinArtifactsPythonPath();

  try {
    const { stdout } = await execFileAsync(
      pythonPath,
      ["-c", "import regipy; print(getattr(regipy, '__version__', 'unknown'))"],
      { timeout: 5_000 }
    );
    return NextResponse.json({
      available: true,
      path: pythonPath,
      version: stdout.trim() || null,
    });
  } catch {
    return NextResponse.json({ available: false, path: pythonPath, version: null });
  }
}
