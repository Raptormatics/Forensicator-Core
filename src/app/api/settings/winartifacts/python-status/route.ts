export const runtime = "nodejs";
export const dynamic = "force-dynamic";
import { execFile } from "child_process";
import { promisify } from "util";
import { NextRequest, NextResponse } from "next/server";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";
import { getWinArtifactsPythonPath, getWinArtifactsBitsPythonPath } from "@/lib/settings/system";

const execFileAsync = promisify(execFile);

async function checkImport(pythonPath: string, moduleName: string, versionExpr: string) {
  try {
    const { stdout } = await execFileAsync(
      pythonPath,
      ["-c", `import ${moduleName}; print(${versionExpr})`],
      { timeout: 5_000 }
    );
    return { available: true, path: pythonPath, version: stdout.trim() || null };
  } catch {
    return { available: false, path: pythonPath, version: null };
  }
}

// GET — any authenticated user, read-only, no admin gate (same tier as the
// tshark-status/volatility-status routes). Checks both the interpreter
// itself and that regipy/bits_parser actually import, since a venv can
// exist without its packages installed. regipy and bits_parser are
// checked against SEPARATE venvs (getWinArtifactsBitsPythonPath()'s own
// comment explains why they can never share one) — reported as "bits"
// alongside the original top-level regipy fields so existing callers of
// this route don't need to change.
export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const pythonPath = await getWinArtifactsPythonPath();
  const bitsPythonPath = await getWinArtifactsBitsPythonPath();

  const [regipyStatus, bitsStatus] = await Promise.all([
    checkImport(pythonPath, "regipy", "getattr(regipy, '__version__', 'unknown')"),
    checkImport(bitsPythonPath, "bits.bits", "'ok'"),
  ]);

  return NextResponse.json({ ...regipyStatus, bits: bitsStatus });
}
