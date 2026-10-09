/**
 * One-time Ed25519 keypair generation for signing update packages.
 *
 * Run once by the vendor (not the appliance). Writes the PUBLIC key to
 * deploy/update-public-key.pem (safe to commit — it only verifies
 * signatures). Prints the PRIVATE key to stdout and does NOT write it
 * anywhere on disk — copy it into a password manager or offline store
 * immediately. Whoever holds it can sign packages this appliance's
 * update script will trust.
 *
 * Usage:
 *   npx tsx scripts/generate-update-keys.ts
 */
import { generateKeyPairSync } from "crypto";
import { writeFileSync, existsSync } from "fs";
import path from "path";

const PUBLIC_KEY_PATH = path.join(__dirname, "..", "deploy", "update-public-key.pem");

if (existsSync(PUBLIC_KEY_PATH)) {
  console.error(`Refusing to overwrite existing ${PUBLIC_KEY_PATH}.`);
  console.error("Delete it first if you really mean to rotate the update signing key");
  console.error("(every previously-issued .fpk package will stop verifying).");
  process.exit(1);
}

const { publicKey, privateKey } = generateKeyPairSync("ed25519");

const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

writeFileSync(PUBLIC_KEY_PATH, publicPem, { mode: 0o644 });

console.log(`Public key written to ${PUBLIC_KEY_PATH} — commit this file.`);
console.log("");
console.log("=".repeat(72));
console.log("PRIVATE KEY — copy this somewhere safe now. It is not saved to disk");
console.log("by this script and will not be shown again.");
console.log("=".repeat(72));
console.log(privatePem);
console.log("=".repeat(72));
