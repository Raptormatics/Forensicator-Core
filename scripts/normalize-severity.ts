/**
 * One-off data fix: normalize every Finding.severity and TimelineEvent.severity
 * to the canonical native vocabulary (Important/Notable/Interesting/
 * Informational — see src/lib/severity.ts). Existing rows can hold either
 * that vocabulary or the classic Critical/High/Medium/Low one, depending on
 * how old the data is / which collector version produced it.
 *
 * Idempotent — safe to re-run; only rows whose value actually changes are
 * updated.
 *
 * Usage:
 *   npx tsx scripts/normalize-severity.ts
 */
import { PrismaClient } from "@prisma/client";
import { normalizeSeverity } from "../src/lib/severity";

const prisma = new PrismaClient();

async function normalizeTable(
  label: string,
  findMany: () => Promise<{ id: string; severity: string }[]>,
  update: (id: string, severity: string) => Promise<unknown>
) {
  const rows = await findMany();
  let changed = 0;
  for (const row of rows) {
    const next = normalizeSeverity(row.severity);
    if (next !== row.severity) {
      await update(row.id, next);
      changed++;
    }
  }
  console.log(`${label}: ${changed} of ${rows.length} rows updated`);
}

async function main() {
  await normalizeTable(
    "Finding",
    () => prisma.finding.findMany({ select: { id: true, severity: true } }),
    (id, severity) => prisma.finding.update({ where: { id }, data: { severity } })
  );

  await normalizeTable(
    "TimelineEvent",
    () => prisma.timelineEvent.findMany({ select: { id: true, severity: true } }),
    (id, severity) => prisma.timelineEvent.update({ where: { id }, data: { severity } })
  );
}

main()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());
