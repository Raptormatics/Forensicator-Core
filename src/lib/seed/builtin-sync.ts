/**
 * Keeps the database copies of the bundled built-ins — Log Analysis
 * decoders and Windows/Linux artifact rules — in step with the code.
 *
 * Both live in the database (custom ones sit next to them), so a release
 * that fixes a decoder or adds a rule changed nothing on an existing
 * instance until an admin pressed "Seed Built-ins". This runs once at server
 * start and re-seeds only when the bundled definitions differ from what was
 * last seeded (a fingerprint kept in a marker file in the app directory), so
 * every update path — in-app, CLI, Docker image — picks them up. Both seeds
 * keep each built-in's enabled/disabled state.
 */
import crypto from "crypto";
import fs from "fs";
import path from "path";

const MARKER = path.join(process.cwd(), ".builtin-seed-fingerprint");
const DECODERS_DIR = path.join(process.cwd(), "src/lib/log-analysis/built-in-decoders");

async function fingerprint(): Promise<string> {
  const { BUILTIN_RULES } = await import("@/lib/windows-artifacts/rule-engine/seed");
  const hash = crypto.createHash("sha256");
  for (const f of fs.readdirSync(DECODERS_DIR).filter((n) => /\.ya?ml$/.test(n)).sort()) {
    hash.update(f).update(fs.readFileSync(path.join(DECODERS_DIR, f)));
  }
  hash.update(JSON.stringify(BUILTIN_RULES));
  return hash.digest("hex");
}

export async function syncBuiltinsIfChanged(): Promise<void> {
  try {
    const fp = await fingerprint();
    let last = "";
    try { last = fs.readFileSync(MARKER, "utf8").trim(); } catch { /* first run */ }
    if (last === fp) return;

    const { seedBuiltinDecoders } = await import("@/lib/log-analysis/decoder-engine/seed");
    const { seedBuiltinWinArtifactRules } = await import("@/lib/windows-artifacts/rule-engine/seed");
    const decoders = await seedBuiltinDecoders();
    const rules = await seedBuiltinWinArtifactRules();
    console.log(`[builtins] Re-seeded ${decoders.seeded.length} decoder(s) and ${rules.seeded.length} artifact rule(s)` +
      (decoders.errors.length + rules.errors.length > 0 ? ` (${decoders.errors.length + rules.errors.length} failed)` : ""));
    try { fs.writeFileSync(MARKER, fp + "\n"); } catch (err) {
      console.warn("[builtins] Couldn't write the seed marker — will re-seed again next start:", err instanceof Error ? err.message : err);
    }
  } catch (err) {
    // Never block startup on this (the database may not be reachable yet).
    console.warn("[builtins] Built-in sync skipped:", err instanceof Error ? err.message : err);
  }
}
