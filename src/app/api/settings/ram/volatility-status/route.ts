export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { getVolatilityPath } from "@/lib/settings/system";

const execFileAsync = promisify(execFile);

// GET — any authenticated user, read-only, no admin gate (same tier as the
// tshark-status route). `vol` has no --version flag, so the version is read
// via the venv's own python3 binary (same bin/ directory as `vol`) instead —
// confirmed against a real Volatility3 install: `vol -h` exits 0 with no
// version banner, but volatility3.framework.constants.PACKAGE_VERSION does
// carry it.
export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const volatilityPath = await getVolatilityPath();
  const pythonPath = path.join(path.dirname(volatilityPath), "python3");

  try {
    await execFileAsync(volatilityPath, ["-h"], { timeout: 5_000 });
    const { stdout } = await execFileAsync(
      pythonPath,
      ["-c", "import volatility3.framework.constants as c; print(c.PACKAGE_VERSION)"],
      { timeout: 5_000 }
    );
    return NextResponse.json({
      available: true,
      path: volatilityPath,
      version: stdout.trim() || null,
    });
  } catch {
    return NextResponse.json({ available: false, path: volatilityPath, version: null });
  }
}
