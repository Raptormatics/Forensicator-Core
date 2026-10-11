import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";

type Params = { params: Promise<{ id: string }> };

// ── DELETE /api/ram-analysis/symbols/[id] ──────────────────────────────────
export async function DELETE(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    await requireAuth(req);
    const symbolTable = await prisma.ramSymbolTable.delete({ where: { id: params.id } });
    fs.unlink(symbolTable.storagePath, () => {});
    return NextResponse.json({ ok: true });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
