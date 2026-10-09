/**
 * Local, offline verification of a .lic file — no network access; works
 * fully air-gapped. Verifies against deploy/license-public-key.pem,
 * issued by the separate forensicator-license service (a different
 * keypair from the update-signing ones in this repo — rotating one
 * shouldn't force rotating the others).
 *
 * Format: base64url(JSON payload) + "." + base64url(Ed25519 signature) —
 * deliberately JWT-shaped for easy inspection, not a bespoke binary format.
 *
 * Core-only purpose: gating the Enterprise overlay (see
 * src/lib/license/activation.ts) — a valid .lic here means this instance
 * is entitled to download and apply it. Once applied, Enterprise's own
 * (much larger) license-enforcement module takes over ongoing validity
 * checks; this file's only job is the one-time entitlement gate.
 */
import { createPublicKey, verify as edVerify } from "crypto";
import fs from "fs";
import path from "path";

// process.cwd(), not require.resolve — this module also loads inside the
// Next.js server bundle, where webpack rewrites require.resolve() to a
// bundle-internal path instead of a real one.
const PUBLIC_KEY_PATH = path.join(process.cwd(), "deploy", "license-public-key.pem");

// Mirrors forensicator-license's src/types.ts (the issuer) — keep both in
// sync by hand; there's no shared package between the two repos.
export const LICENSE_TYPES = ["subscription", "trial"] as const;
export type LicenseType = (typeof LICENSE_TYPES)[number];

/** Ordered low-to-high — planAtLeast() in the overlay's license/types.ts
 * depends on this order, not just set membership. */
export const PLANS = ["professional", "enterprise"] as const;
export type Plan = (typeof PLANS)[number];

export type LicensePayload = {
  licenseId: string;
  customerName: string;
  licenseType: LicenseType;
  plan: Plan;
  issuedAt: string;
  expiresAt: string | null;
  graceDays: number;
};

export class InvalidLicenseError extends Error {}

function base64UrlToBuffer(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/** Parses and verifies a .lic file's contents. Throws InvalidLicenseError on any failure. */
export function verifyLicense(licContent: string): LicensePayload {
  const parts = licContent.trim().split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new InvalidLicenseError("Malformed license file.");
  }
  const [encodedPayload, encodedSignature] = parts;

  let publicKeyPem: string;
  try {
    publicKeyPem = fs.readFileSync(PUBLIC_KEY_PATH, "utf8");
  } catch {
    throw new InvalidLicenseError("License public key not found on this build (deploy/license-public-key.pem missing).");
  }

  const publicKey = createPublicKey(publicKeyPem);
  const ok = edVerify(null, Buffer.from(encodedPayload, "utf8"), publicKey, base64UrlToBuffer(encodedSignature));
  if (!ok) throw new InvalidLicenseError("License signature is invalid.");

  let payload: LicensePayload;
  try {
    payload = JSON.parse(base64UrlToBuffer(encodedPayload).toString("utf8"));
  } catch {
    throw new InvalidLicenseError("License payload is not valid JSON.");
  }
  if (!payload.licenseId || !payload.customerName || !payload.licenseType || !payload.plan) {
    throw new InvalidLicenseError("License payload is missing required fields.");
  }
  if (!LICENSE_TYPES.includes(payload.licenseType)) {
    throw new InvalidLicenseError(`Unrecognized license type: ${payload.licenseType}`);
  }
  if (!PLANS.includes(payload.plan)) {
    throw new InvalidLicenseError(`Unrecognized plan: ${payload.plan}`);
  }
  return payload;
}
