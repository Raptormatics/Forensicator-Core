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
import { z } from "zod";
import { getActivationState } from "@/lib/license/activation";
import { getChannel } from "./online";
import { installedVersion } from "./paths";
import { isNewerVersion } from "./version";

const OVERLAY_BASE_URL = "https://updates.forensicator.io/overlay";
const DELTA_STATE_FILE = "/etc/forensicator/enterprise-delta.json";

const latestSchema = z.object({
  version: z.string().min(1),
  requiresCoreVersion: z.string().min(1),
  releaseNotes: z.string().default(""),
  packageUrl: z.string().url(),
  packageSha256: z.string().min(1),
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
