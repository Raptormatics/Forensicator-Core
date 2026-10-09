/**
 * Enterprise-overlay entitlement gate — "has this instance been given a
 * valid license to download and apply the Enterprise overlay." This is
 * deliberately much smaller than Enterprise's own license system
 * (src/lib/license/guard.ts there): no revocation telemetry, no
 * database-backed status, no override. Core has no LicenseStatus model at
 * all (it's one of the models the overlay itself adds) and no ongoing
 * enforcement to do — the license file here only has to answer one
 * question, once, before "Install" is allowed. Ongoing enforcement
 * becomes Enterprise's job the moment the overlay is applied, and the
 * same .lic file carries over — see deploy/forensicator-update.sh's
 * --overlay mode, which seeds Enterprise's own LicenseStatus from this
 * exact file.
 *
 * Stored on disk, not in the database — same reasoning as the update
 * system's .update-channel/.current-progress.json: this has to exist and
 * be readable before/outside of whatever the app's normal DB-backed
 * state can represent.
 */
import fs from "fs";
import path from "path";
import { verifyLicense, InvalidLicenseError, type LicensePayload } from "./verify";

const LIC_PATH = "/etc/forensicator/enterprise.lic";
const DAY_MS = 24 * 60 * 60 * 1000;

export type EnterpriseActivationState = {
  valid: boolean;
  reason: string;
  configured: boolean;
  licenseId: string | null;
  customerName: string | null;
  licenseType: string | null;
  plan: string | null;
  expiresAt: string | null;
};

function evaluate(payload: LicensePayload): EnterpriseActivationState {
  const base = {
    configured: true,
    licenseId: payload.licenseId,
    customerName: payload.customerName,
    licenseType: payload.licenseType,
    plan: payload.plan,
  };

  if (!payload.expiresAt) {
    return { ...base, valid: true, reason: "Licensed.", expiresAt: null };
  }

  const expiresAt = new Date(payload.expiresAt);
  const graceDeadline = expiresAt.getTime() + payload.graceDays * DAY_MS;

  if (Date.now() > graceDeadline) {
    return { ...base, valid: false, reason: `License expired on ${expiresAt.toDateString()}.`, expiresAt: payload.expiresAt };
  }
  if (Date.now() > expiresAt.getTime()) {
    const daysLeft = Math.ceil((graceDeadline - Date.now()) / DAY_MS);
    return { ...base, valid: true, reason: `License expired — operating in a ${daysLeft}-day grace period.`, expiresAt: payload.expiresAt };
  }
  return { ...base, valid: true, reason: "Licensed.", expiresAt: payload.expiresAt };
}

const NOT_CONFIGURED: EnterpriseActivationState = {
  valid: false,
  reason: "No Enterprise license activated.",
  configured: false,
  licenseId: null,
  customerName: null,
  licenseType: null,
  plan: null,
  expiresAt: null,
};

/** Current activation state — reads and re-verifies the .lic on every call, never cached. */
export function getActivationState(): EnterpriseActivationState {
  let licContent: string;
  try {
    licContent = fs.readFileSync(LIC_PATH, "utf8");
  } catch {
    return NOT_CONFIGURED;
  }

  try {
    return evaluate(verifyLicense(licContent));
  } catch (err) {
    return {
      ...NOT_CONFIGURED,
      configured: true,
      reason: err instanceof InvalidLicenseError ? err.message : "License verification failed.",
    };
  }
}

/** Verifies and stores a .lic file's raw content. Throws InvalidLicenseError if invalid. */
export function activateLicense(licContent: string): EnterpriseActivationState {
  const payload = verifyLicense(licContent); // throws on invalid — nothing is written
  fs.mkdirSync(path.dirname(LIC_PATH), { recursive: true });
  fs.writeFileSync(LIC_PATH, licContent.trim(), { mode: 0o600 });
  return evaluate(payload);
}
