/**
 * Seed the single organization for an appliance instance — no user.
 *
 * Appliance mode is scoped to exactly one Organization (ORG_NAME /
 * ORG_SLUG, set at provision time), but the one user Core ever has is no
 * longer seeded automatically — they create their own account through
 * the mandatory /setup wizard on first visit (POST /api/setup links them
 * to this org — Core has no RBAC, so there's no role to assign). This
 * script only ever creates the org itself, so first-boot.sh can run it
 * unattended before the app is ever reachable, with nothing left to
 * transcribe off a console.
 *
 * Usage:
 *   ORG_NAME="Acme Corp" ORG_SLUG=acme npx tsx scripts/seed-org.ts
 */
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  const orgName = process.env.ORG_NAME ?? "Default Organization";
  const orgSlug = process.env.ORG_SLUG ?? "default";

  const org = await prisma.organization.upsert({
    where: { slug: orgSlug },
    update: { name: orgName },
    create: { name: orgName, slug: orgSlug },
  });

  console.log(`✅ Organization ready: ${org.name} (${org.slug})`);
}

main()
  .catch(e => { console.error("❌ Error:", e); process.exit(1); })
  .finally(() => prisma.$disconnect());
