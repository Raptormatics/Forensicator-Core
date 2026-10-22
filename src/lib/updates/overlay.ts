/**
 * "Check for the Enterprise overlay" — a separate channel from Core's own
 * updates (see online.ts), fixed at the vendor's own distribution point
 * rather than configurable per-deployment: there's exactly one legitimate
 * place to get a real overlay package, unlike UPDATE_SERVER_URL, which a
 * self-hosted mirror could point elsewhere for regular Core updates.
 *
 * This is a perpetual, versioned channel, not a one-time install — the
 * first successful apply turns Core into Enterprise, and every later one
 * is just a newer overlay version on top of whatever Core release is
 * currently installed. Two version numbers exist independently from the
 * first apply onward: Core's own (package.json, read via
 * src/lib/updates/paths.ts's installedVersion()) and the overlay's own
 * (CONFIG_DIR/enterprise-delta.json, read here).
 *
 * The package itself is not publicly downloadable: latest.json (public)
 * only says which version is current, and the .fpk is fetched from the
 * license server, which streams it only to a caller presenting an
 * issued, active license (downloadOverlayPackage() below).
 *
 * Gated on an already-activated license (src/lib/license/activation.ts) —
 * same low-trust-response posture as online.ts's own security note:
 * this only tells the admin *where* to look. Whatever it points to still
 * has to pass Ed25519 signature verification AND the requiresCoreVersion
 * ordering check in deploy/forensicator-update.sh's --overlay mode
 * before anything is installed — this module's own comparisons below
 * are a UX convenience (disable the button, show why), not the trust
 * boundary.
 */
import fs from "fs";
import { createHash } from "crypto";
import { z } from "zod";
import { getActivationState, readActivatedLicense } from "@/lib/license/activation";
import { getChannel } from "./online";
import { installedVersion } from "./paths";
import { isNewerVersion } from "./version";

const OVERLAY_BASE_URL = "https://updates.forensicator.io/overlay";
// Where licensed overlay downloads come from — the vendor's license service.
// LICENSE_SERVER_URL overrides it (the same variable Enterprise's check-in uses).
const LICENSE_SERVER_URL = (process.env.LICENSE_SERVER_URL || "https://license.forensicator.io").replace(/\/+$/, "");
const DELTA_STATE_FILE = "/etc/forensicator/enterprise-delta.json";

const latestSchema = z.object({
  version: z.string().min(1),
  requiresCoreVersion: z.string().min(1),
  releaseNotes: z.string().default(""),
  packageSha256: z.string().min(1),
  // Deprecated, always empty now — latest.json no longer carries a download
  // URL. Kept in the type only so an already-installed overlay whose own
  // copy of the install route still reads it (<= 1.1.1) keeps compiling
  // when Core updates underneath it, until the overlay itself is updated.
  packageUrl: z.string().default(""),
  packageSize: z.number().nonnegative().optional(),
  publishedAt: z.string().optional(),
});
export type LatestOverlayInfo = z.infer<typeof latestSchema>;

export type DeltaState = {
  applied: boolean;
  version: string | null;
  requiresCoreVersion: string | null;
  appliedAt: string | null;
};

const NOT_APPLIED: DeltaState = { applied: false, version: null, requiresCoreVersion: null, appliedAt: null };

/** Current overlay/delta state — independent of Core's own version. */
export function getDeltaState(): DeltaState {
  try {
    const raw = JSON.parse(fs.readFileSync(DELTA_STATE_FILE, "utf8"));
    return {
      applied: true,
      version: raw.version ?? null,
      requiresCoreVersion: raw.requiresCoreVersion ?? null,
      appliedAt: raw.appliedAt ?? null,
    };
  } catch {
    return NOT_APPLIED;
  }
}

export type OverlayCheckResult =
  | { licensed: false }
  | {
      licensed: true;
      ok: true;
      latest: LatestOverlayInfo;
      /** Newer than whatever delta version (if any) is currently applied. */
      updateAvailable: boolean;
      /** Whether the installed Core version meets latest.requiresCoreVersion — the
       *  same check deploy/forensicator-update.sh enforces authoritatively; shown
       *  here so the UI can explain *why* Install is disabled before the user tries. */
      coreVersionSatisfied: boolean;
    }
  | { licensed: true; ok: false; error: string };

export async function checkForOverlay(): Promise<OverlayCheckResult> {
  if (!getActivationState().valid) return { licensed: false };

  const channel = getChannel();
  try {
    const res = await fetch(`${OVERLAY_BASE_URL}/${channel}/latest.json`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      return { licensed: true, ok: false, error: `Overlay server returned HTTP ${res.status}` };
    }
    const parsed = latestSchema.safeParse(await res.json());
    if (!parsed.success) {
      return { licensed: true, ok: false, error: "Overlay server response did not match the expected format." };
    }

    const delta = getDeltaState();
    const updateAvailable = !delta.applied || isNewerVersion(parsed.data.version, delta.version!);
    const coreVersionSatisfied = !isNewerVersion(parsed.data.requiresCoreVersion, installedVersion());

    return { licensed: true, ok: true, latest: parsed.data, updateAvailable, coreVersionSatisfied };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { licensed: true, ok: false, error: `Could not reach the overlay server: ${message}` };
  }
}

const MAX_PACKAGE_BYTES = 500 * 1024 * 1024;

/**
 * Download overlay `version` from the license server, authenticated with the
 * activated license, and check it against latest.json's SHA-256. Returns the
 * package bytes, or an error message (e.g. the license server refused the
 * license as revoked or expired).
 */
export async function downloadOverlayPackage(latest: LatestOverlayInfo): Promise<{ ok: true; bytes: Buffer } | { ok: false; error: string }> {
  const licContent = readActivatedLicense();
  if (!licContent) return { ok: false, error: "No Enterprise license activated — activate one under Settings -> License first." };

  let res: Response;
  try {
    res = await fetch(`${LICENSE_SERVER_URL}/overlay/package`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ licContent, version: latest.version }),
      signal: AbortSignal.timeout(300_000),
    });
  } catch (err) {
    return { ok: false, error: `Could not reach the license server: ${err instanceof Error ? err.message : String(err)}` };
  }
  if (!res.ok) {
    const detail = await res.json().then((d: { error?: string }) => d.error).catch(() => null);
    return { ok: false, error: `The license server refused the download (HTTP ${res.status})${detail ? `: ${detail}` : ""}` };
  }
  const bytes = Buffer.from(await res.arrayBuffer());
  if (bytes.length > MAX_PACKAGE_BYTES) return { ok: false, error: "Downloaded package exceeds the 500 MB limit." };
  if (createHash("sha256").update(bytes).digest("hex") !== latest.packageSha256) {
    return { ok: false, error: "Downloaded package's checksum does not match the overlay server's manifest — refusing to install." };
  }
  return { ok: true, bytes };
}
