import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { prisma } from "@/lib/db/prisma";
import { requireAuth, orgWhere } from "@/lib/auth/api-guard";
import { getVolatilitySymbolsDir } from "@/lib/settings/system";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Mirrors Volatility3's own constants.ISF_EXTENSIONS — anything else isn't
// a real Intermediate Symbol Format file.
const ALLOWED_EXTENSIONS = [".json", ".json.xz", ".json.gz", ".json.bz2"];
const MAX_BYTES = 200 * 1024 * 1024; // 200MB — generous for even a large kernel's ISF, nowhere near memory-dump scale
const ALLOWED_OS_TYPES = ["linux", "mac"];

function matchedExtension(filename: string): string | null {
  const lower = filename.toLowerCase();
  return ALLOWED_EXTENSIONS.find((ext) => lower.endsWith(ext)) ?? null;
}

// ── GET /api/ram-analysis/symbols ──────────────────────────────────────────
export async function GET(req: NextRequest) {
  try {
    const actor = await requireAuth(req);
    const where = orgWhere(actor);

    const symbolTables = await prisma.ramSymbolTable.findMany({
      where: { ...where },
      orderBy: { createdAt: "desc" },
      select: {
        id: true, osType: true, filename: true, description: true, fileSize: true,
        createdAt: true,
        uploadedBy: { select: { email: true, name: true } },
        organization: { select: { id: true, name: true } },
      },
    });

    return NextResponse.json({ symbolTables });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}

// ── POST /api/ram-analysis/symbols ─────────────────────────────────────────
// Ordinary buffered upload (unlike the RAM dump route) — ISF files run KBs
// to tens of MBs, nowhere near the scale that forced the streaming design
// for memory images.
export async function POST(req: NextRequest) {
  try {
    const actor = await requireAuth(req);

    const formData    = await req.formData();
    const file        = formData.get("file");
    const osType      = String(formData.get("osType") ?? "").trim();
    const description = String(formData.get("description") ?? "").trim() || null;
    const orgId       = String(formData.get("organizationId") ?? "").trim() || null;

    if (!file || typeof file === "string" || !("arrayBuffer" in file)) {
      return NextResponse.json({ error: "missing_file", message: "Provide a file in the 'file' field." }, { status: 400 });
    }
    if (!ALLOWED_OS_TYPES.includes(osType)) {
      return NextResponse.json({ error: "invalid_os_type", message: "osType must be 'linux' or 'mac'." }, { status: 400 });
    }
    const ext = matchedExtension(file.name);
    if (!ext) {
      return NextResponse.json({ error: "invalid_file_type", message: `Only ${ALLOWED_EXTENSIONS.join(", ")} ISF files are supported.` }, { status: 400 });
    }
    if (file.size > MAX_BYTES) {
      return NextResponse.json({ error: "file_too_large", message: `Maximum symbol table size is ${(MAX_BYTES / 1024 / 1024).toFixed(0)} MB.` }, { status: 413 });
    }

    const buffer = Buffer.from(await file.arrayBuffer());

    const symbolTable = await prisma.ramSymbolTable.create({
      data: {
        osType, filename: file.name, description, fileSize: buffer.length,
        storagePath: "", // set below once we know the id
        uploadedById: actor.id,
        organizationId: orgId ?? (actor.organizationIds[0] ?? null),
      },
    });

    // Placed under a linux/ or mac/ subdirectory of the configured symbols
    // dir on purpose — Volatility3's -s/--symbol-dirs extends the
    // volatility3.symbols namespace package's own search path, and that
    // package only discovers ISF files living under a linux/ or mac/
    // subpackage, mirroring the official downloadable symbol-pack layout.
    const symbolsDir = await getVolatilitySymbolsDir();
    const osSubdir = path.join(symbolsDir, osType);
    fs.mkdirSync(osSubdir, { recursive: true });
    const storagePath = path.join(osSubdir, `${symbolTable.id}-${file.name}`);
    fs.writeFileSync(storagePath, buffer);

    const updated = await prisma.ramSymbolTable.update({
      where: { id: symbolTable.id },
      data: { storagePath },
    });

    return NextResponse.json({ symbolTable: updated }, { status: 201 });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    console.error("[ram-analysis/symbols] error:", err);
    return NextResponse.json({ error: "server_error", message: String(err) }, { status: 500 });
  }
}
