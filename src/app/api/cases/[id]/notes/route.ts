export const runtime = "nodejs";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActor } from "@/lib/auth/actor";
import { guardCaseOpen } from "@/lib/cases/case-lock";

type Params = { params: Promise<{ id: string }> };

export async function POST(req: NextRequest, props: Params) {
  const params = await props.params;
  const actor = await getActor(req);
  const locked = await guardCaseOpen({ caseId: params.id }, "adding notes");
  if (locked) return locked;
  const { content } = await req.json();
  if (!content?.trim())
    return NextResponse.json({ error: "content required" }, { status: 400 });

  const note = await prisma.caseNote.create({
    data: { caseId: params.id, authorId: actor.id, content: content.trim() },
  });
  return NextResponse.json({ note }, { status: 201 });
}
