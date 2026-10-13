export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { getActorOrThrow, AuthError } from "@/lib/auth/api-guard";

const MAX_FILE_BYTES = 10 * 1024 * 1024; // 10MB — NSRL-style sets run larger than IOC lists
const MAX_LINES = 200_000;

// MD5/SHA1/SHA256 only — matching is algorithm-agnostic string equality
// against Evidence.hash (a single untyped field, no per-algorithm column),
// so there's no need to classify which of the three a given line is.
const RE_HASH = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;

/**
 * POST /api/known-hashes/import — bulk-add known-good file hashes (one per
 * line, optionally "hash,note" CSV-style — anything after the first comma
 * is kept as a note) from an uploaded plaintext/CSV file, into a specific
 * case. Lines starting with # and blank lines are ignored; anything that
 * doesn't parse as a 32/40/64-hex-char hash is reported back as skipped.
 */
export async function POST(req: NextRequest) {
  let actor;
  try { actor = await getActorOrThrow(req); }
  catch (e) { if (e instanceof AuthError) return e.toResponse(); throw e; }

  const formData = await req.formData();
  const file = formData.get("file");
  if (!(file instanceof File)) {
    return NextResponse.json({ error: "missing_file", message: "Upload a .txt or .csv file in the form field named file." }, { status: 400 });
  }
  if (file.size > MAX_FILE_BYTES) {
    return NextResponse.json({ error: "file_too_large", message: "File is limited to 10MB." }, { status: 413 });
  }
  const caseId = formData.get("caseId");
  if (typeof caseId !== "string" || !caseId) {
    return NextResponse.json({ error: "missing_case", message: "caseId is required." }, { status: 400 });
  }
  const source = formData.get("source") === "nsrl" ? "nsrl" : "custom";

  const text = await file.text();
  const rawLines = text.split(/\r?\n/);
  const truncated = rawLines.length > MAX_LINES;
  const lines = rawLines.slice(0, MAX_LINES);

  const seen = new Set<string>();
  const hits: { hash: string; note: string | null }[] = [];
  let skipped = 0;
  const skippedSamples: string[] = [];

  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [hashPart, ...rest] = line.split(",");
    const hash = hashPart.trim().toLowerCase();
    if (!RE_HASH.test(hash)) {
      skipped++;
      if (skippedSamples.length < 10) skippedSamples.push(line.slice(0, 80));
      continue;
    }
    if (seen.has(hash)) continue;
    seen.add(hash);
    const note = rest.join(",").trim();
    hits.push({ hash, note: note || null });
  }

  if (hits.length > 0) {
    await prisma.knownHash.createMany({
      data: hits.map((h) => ({ hash: h.hash, source, note: h.note })),
      skipDuplicates: true,
    });
  }

  // Link every hit to this case — a hash already known globally from a
  // different case's import still needs its own CaseKnownHash row here to
  // be treated as known-good in *this* case.
  let linked = 0;
  if (hits.length > 0) {
    const knownHashes = await prisma.knownHash.findMany({
      where: { hash: { in: hits.map((h) => h.hash) } },
      select: { id: true },
    });
    const result = await prisma.caseKnownHash.createMany({
      data: knownHashes.map((kh) => ({ caseId, knownHashId: kh.id, createdById: actor.id })),
      skipDuplicates: true,
    });
    linked = result.count;
  }

  await prisma.activityLog.create({
    data: {
      userId: actor.id,
      action: "known_hash_import",
      entityType: "known_hash",
      entityId: "bulk",
      metadata: {
        filename: file.name, caseId, total: hits.length, linked, skipped,
      } as never,
    },
  });

  return NextResponse.json({
    total: hits.length,
    linked,
    skipped,
    skippedSamples,
    truncated,
  });
}
