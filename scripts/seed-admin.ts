/**
 * Seed the first admin user — a dev/testing convenience that bypasses the
 * /setup wizard. Forensicator Core always runs in appliance mode: seeds
 * exactly one Organization (ORG_NAME / ORG_SLUG) and an org_admin user as
 * its sole member.
 *
 * Usage:
 *   npx tsx scripts/seed-admin.ts
 *
 * Or with custom credentials:
 *   ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=changeme123 npx tsx scripts/seed-admin.ts
 */
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  const email    = process.env.ADMIN_EMAIL    ?? "admin@forensicator.local";
  const password = process.env.ADMIN_PASSWORD ?? "Forensicator1!";
  const name     = process.env.ADMIN_NAME     ?? "Organization Admin";
  const role     = "org_admin";

  console.log(`\n🔐 Seeding ${role} user: ${email}`);

  const passwordHash = await bcrypt.hash(password, 12);

  const user = await prisma.user.upsert({
    where:  { email },
    update: { passwordHash, role, isActive: true, name },
    create: {
      email,
      passwordHash,
      name,
      role,
      isActive: true,
    },
  });

  const orgName = process.env.ORG_NAME ?? "Default Organization";
  const orgSlug = process.env.ORG_SLUG ?? "default";

  const org = await prisma.organization.upsert({
    where:  { slug: orgSlug },
    update: { name: orgName },
    create: { name: orgName, slug: orgSlug },
  });

  await prisma.organizationMember.upsert({
    where:  { organizationId_userId: { organizationId: org.id, userId: user.id } },
    update: { role: "org_admin", active: true },
    create: { organizationId: org.id, userId: user.id, role: "org_admin", joinedAt: new Date() },
  });

  console.log(`✅ Organization ready: ${org.name} (${org.slug})`);
  console.log(`✅ Admin user ready:`);
  console.log(`   ID:    ${user.id}`);
  console.log(`   Email: ${user.email}`);
  console.log(`   Role:  ${user.role}`);
  console.log(`\n⚠️  Change the default password immediately after first login.\n`);
}

main()
  .catch(e => { console.error("❌ Error:", e); process.exit(1); })
  .finally(() => prisma.$disconnect());
