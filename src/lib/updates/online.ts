/**
 * Online "Check for Updates" — same optional-config pattern as
 * LICENSE_SERVER_URL (src/lib/license/checkin.ts): unset means the feature
 * is simply off, no network calls ever made.
 *
 * Security note: this path is intentionally low-trust. The JSON response
 * below only tells the admin *where* to look — it is never treated as
 * authorization to install anything. Whatever it points to still has to
 * pass through the exact same Ed25519 signature verification, checksum
 * check, and downgrade protection in deploy/forensicator-update.sh as an
 * offline upload does. A compromised or spoofed update server could at
 * worst point an admin at the wrong (but still validly-signed) package —
 * it cannot get an unsigned or tampered one installed.
 */
import fs from "fs";
import path from "path";
import { z } from "zod";
import { APP_DIR } from "./paths";

export const CHANNELS = ["stable", "beta", "preview"] as const;
export type Channel = (typeof CHANNELS)[number];

// Deliberately NOT inside APP_DIR's git-tracked content, so it survives an
// update (release tarball extraction only ever adds/overwrites tracked
// files — see deploy/forensicator-update.sh).
const CHANNEL_FILE = path.join(APP_DIR, ".update-channel");

export function isUpdateServerConfigured(): boolean {
  return Boolean(process.env.UPDATE_SERVER_URL);
}

export function getChannel(): Channel {
  try {
    const raw = fs.readFileSync(CHANNEL_FILE, "utf8").trim();
    if ((CHANNELS as readonly string[]).includes(raw)) return raw as Channel;
  } catch {
    // fall through to default
  }
  return "stable";
}

export function setChannel(channel: Channel): void {
  fs.writeFileSync(CHANNEL_FILE, channel, { mode: 0o644 });
}

const latestSchema = z.object({
  version: z.string().min(1),
  releaseNotes: z.string().default(""),
  packageUrl: z.string().url(),
  packageSha256: z.string().min(1),
  packageSize: z.number().nonnegative().optional(),
  publishedAt: z.string().optional(),
});
export type LatestUpdateInfo = z.infer<typeof latestSchema>;

export type CheckResult =
  | { configured: false }
  | { configured: true; ok: true; latest: LatestUpdateInfo }
  | { configured: true; ok: false; error: string };

/**
 * Contract expected of the update server: GET {UPDATE_SERVER_URL}/{channel}/latest.json
 * returning the shape validated by `latestSchema` above.
 */
export async function checkForUpdate(): Promise<CheckResult> {
  if (!isUpdateServerConfigured()) return { configured: false };

  const base = process.env.UPDATE_SERVER_URL!.replace(/\/+$/, "");
  const channel = getChannel();

  try {
    const res = await fetch(`${base}/${channel}/latest.json`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      return { configured: true, ok: false, error: `Update server returned HTTP ${res.status}` };
    }
    const parsed = latestSchema.safeParse(await res.json());
    if (!parsed.success) {
      return { configured: true, ok: false, error: "Update server response did not match the expected format." };
    }
    return { configured: true, ok: true, latest: parsed.data };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { configured: true, ok: false, error: `Could not reach the update server: ${message}` };
  }
}
