// ─────────────────────────────────────────────────────────────────────────────
// Built-in Decoder Seed — inserts bundled YAML decoders into the database.
//
// Called from the /api/log-analysis/decoders/seed route (admin only).
// Safe to call multiple times — uses upsert.
// ─────────────────────────────────────────────────────────────────────────────

import path from "path";
import fs   from "fs";

import { prisma }          from "@/lib/db/prisma";
import { compileDecoder }  from "./engine";

const DECODERS_DIR = path.join(process.cwd(), "src/lib/log-analysis/built-in-decoders");

/** Return all .yaml files in the built-in-decoders directory */
function listBuiltinYamlFiles(): string[] {
  try {
    return fs
      .readdirSync(DECODERS_DIR)
      .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))
      .map((f) => path.join(DECODERS_DIR, f));
  } catch {
    return [];
  }
}

export interface SeedResult {
  seeded: string[];
  errors: { file: string; error: string }[];
}

/**
 * Read all bundled YAML files, compile them, and insert into the DB.
 *
 * Performs a clean copy: all existing built-in rows are deleted first so stale
 * or renamed decoders are removed. Each decoder's enabled state is preserved
 * (disabled decoders stay disabled across re-seeds).
 */
export async function seedBuiltinDecoders(): Promise<SeedResult> {
  const files = listBuiltinYamlFiles();
  const seeded: string[] = [];
  const errors: { file: string; error: string }[] = [];

  // Remember which decoders were explicitly disabled so we can restore that
  // state after the wipe.
  const existing = await prisma.logDecoder.findMany({
    where:  { isBuiltin: true },
    select: { name: true, enabled: true },
  });
  const enabledByName = new Map(existing.map((d) => [d.name, d.enabled]));

  // Wipe all built-in rows for a clean copy.
  await prisma.logDecoder.deleteMany({ where: { isBuiltin: true } });

  for (const filepath of files) {
    const filename = path.basename(filepath);
    try {
      const yamlContent = fs.readFileSync(filepath, "utf-8");
      const def = compileDecoder(yamlContent, true);

      // Preserve the previous enabled state; default to true for new decoders.
      const enabled = enabledByName.get(def.name) ?? true;

      await prisma.logDecoder.create({
        data: {
          name:        def.name,
          title:       def.title ?? null,
          description: def.description ?? null,
          yamlContent,
          enabled,
          isBuiltin:   true,
          version:     1,
        },
      });

      seeded.push(def.name);
    } catch (err) {
      errors.push({ file: filename, error: String(err) });
    }
  }

  return { seeded, errors };
}
