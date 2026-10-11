/**
 * GET /api/ram-analysis/uploads/[id]/malfind-regions/[regionId]/dump — re-invokes
 * windows.malware.malfind.Malfind scoped to the region's process with `--dump`,
 * which uses Volatility3's own virtual-to-physical address translation to write
 * the real VAD bytes to disk (a naive raw file-offset read at the VAD's virtual
 * address would be wrong). Volatility3 names the file
 * `pid.<pid>.vad.<start>-<end>.dmp` (confirmed against the installed framework's
 * vadinfo.py vad_dump()) — `--pid` dumps every suspicious VAD for that process,
 * so the specific file matching this region's stored start/end address is picked
 * out of however many land in the scratch output directory.
 *
 * Windows-only for now — Linux/macOS malfind already embeds a small preview
 * directly in its normal pass (see mappers.ts), and don't yet support a
 * VAD-scoped `--dump` equivalent to re-invoke here.
 */
import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { getVolatilityPath, getVolatilitySymbolsDir, getRamDir } from "@/lib/settings/system";
import { runVolatilityPlugin } from "@/lib/ram-analysis/volatility";

type Params = { params: Promise<{ id: string; regionId: string }> };

export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  let tmpDir: string | null = null;
  try {
    await requireAuth(req);
    const { id, regionId } = params;

    const region = await prisma.ramMalfindRegion.findUnique({
      where: { id: regionId },
      include: { finding: { select: { uploadId: true, pid: true, processName: true } } },
    });
    if (!region || region.finding.uploadId !== id) {
      return NextResponse.json({ error: "not_found" }, { status: 404 });
    }
    if (region.finding.pid === null || region.startAddress === null || region.endAddress === null) {
      return NextResponse.json({ error: "region_missing_address" }, { status: 400 });
    }

    const upload = await prisma.ramUpload.findUnique({
      where: { id },
      select: { storagePath: true, osType: true },
    });
    if (!upload?.storagePath) {
      return NextResponse.json({ error: "upload_not_found" }, { status: 404 });
    }
    if (upload.osType !== "windows") {
      return NextResponse.json(
        { error: "unsupported_os", message: "Full memory dump is only supported for Windows images currently. Use the inline hex preview above." },
        { status: 400 }
      );
    }

    tmpDir = fs.mkdtempSync(path.join(await getRamDir(), "dumps-"));

    const volPath = await getVolatilityPath();
    const symbolsDir = await getVolatilitySymbolsDir();
    const result = await runVolatilityPlugin(volPath, upload.storagePath, "windows.malware.malfind.Malfind", {
      symbolsDir,
      outputDir: tmpDir,
      pluginArgs: ["--pid", String(region.finding.pid), "--dump"],
    });
    if (result.status !== "ok") {
      const message = result.status === "timeout" ? "Volatility3 timed out re-dumping this region" : result.message;
      return NextResponse.json({ error: "dump_failed", message }, { status: 500 });
    }

    const files = fs.readdirSync(tmpDir);
    const expected = `pid.${region.finding.pid}.vad.${region.startAddress}-${region.endAddress}.dmp`;
    const match =
      files.find((f) => f === expected) ??
      files.find((f) => f.includes(region.startAddress!) && f.includes(region.endAddress!));
    if (!match) {
      return NextResponse.json({ error: "dump_file_not_found" }, { status: 500 });
    }

    const bytes = fs.readFileSync(path.join(tmpDir, match));
    const safeProcess = (region.finding.processName ?? "process").replace(/[^a-zA-Z0-9._-]/g, "_");
    const filename = `${safeProcess}-pid${region.finding.pid}-${region.startAddress}.dmp`;

    return new NextResponse(new Uint8Array(bytes), {
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Content-Length": String(bytes.length),
      },
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  } finally {
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
