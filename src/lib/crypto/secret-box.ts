/**
 * Reversible encryption for third-party credentials stored per-organization
 * (e.g. threat-intel provider API keys). Unlike ApiKey (bcrypt-hashed, only
 * ever compared), these need to be recovered in plaintext to call out to the
 * provider — so this is AES-256-GCM, not a one-way hash.
 */
import { createCipheriv, createDecipheriv, randomBytes, createHash } from "crypto";

function getKey(): Buffer {
  const raw = process.env.ENCRYPTION_KEY ?? process.env.NEXTAUTH_SECRET;
  if (!raw) {
    throw new Error("ENCRYPTION_KEY (or NEXTAUTH_SECRET) must be set to store encrypted secrets");
  }
  // SHA-256 gives a fixed 32-byte key regardless of the input string's length/format.
  return createHash("sha256").update(raw).digest();
}

export function encryptSecret(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", getKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString("base64");
}

export function decryptSecret(stored: string): string {
  const buf = Buffer.from(stored, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ciphertext = buf.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", getKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
