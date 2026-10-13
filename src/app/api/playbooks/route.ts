export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";

// GET /api/playbooks — list available built-in playbooks (for the
// "Incident Type" selector / "Apply Playbook" action on a case).
export async function GET(req: NextRequest) {
  try { await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const playbooks = await prisma.playbook.findMany({
    orderBy: { name: "asc" },
    select: {
      id: true,
      name: true,
      incidentType: true,
      description: true,
      isBuiltin: true,
      _count: { select: { tasks: true } },
    },
  });

  return NextResponse.json({
    playbooks: playbooks.map((p) => ({
      id: p.id,
      name: p.name,
      incidentType: p.incidentType,
      description: p.description,
      isBuiltin: p.isBuiltin,
      taskCount: p._count.tasks,
    })),
  });
}
