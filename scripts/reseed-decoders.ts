#!/usr/bin/env tsx
/**
 * Standalone reseed script — run with:
 *   npx tsx scripts/reseed-decoders.ts
 *
 * Clears all built-in decoder rows and reinserts them from the YAML files,
 * preserving each decoder's enabled/disabled state.
 */
import { seedBuiltinDecoders } from "../src/lib/log-analysis/decoder-engine/seed";

async function main() {
  console.log("Re-seeding built-in decoders...\n");
  const { seeded, errors } = await seedBuiltinDecoders();

  if (seeded.length) {
    console.log(`✓ Seeded ${seeded.length} decoder(s):`);
    for (const name of seeded) console.log(`    ${name}`);
  }

  if (errors.length) {
    console.error(`\n✗ ${errors.length} error(s):`);
    for (const e of errors) console.error(`    ${e.file}: ${e.error}`);
    process.exit(1);
  }

  console.log("\nDone.");
  process.exit(0);
}

main().catch((err) => { console.error(err); process.exit(1); });
