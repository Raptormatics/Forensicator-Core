/**
 * Shared guard for every route that would otherwise try to spawn
 * `sudo deploy/forensicator-update.sh` — structurally impossible inside
 * the Docker image (no sudo, no systemd), not just unconfigured. Returns
 * a ready-to-return NextResponse when blocked, or null to continue as
 * normal. Defense in depth: the Settings → Updates page already hides
 * these actions entirely when containerized, but a direct POST should
 * still get a clear answer, not a silent spawn failure logged nowhere
 * the caller can see.
 */
import { NextResponse } from "next/server";
import { isContainerized } from "@/lib/config/deployment";

export function containerUpdateBlockedResponse(): NextResponse | null {
  if (!isContainerized()) return null;
  return NextResponse.json(
    {
      error:
        "Updates aren't available in the Docker deployment — there's no sudo or systemd inside this container for the installer to use. Pull the latest changes and run `docker compose up -d --build` instead.",
      containerized: true,
    },
    { status: 409 }
  );
}

/**
 * A valid license only ever unlocks installing the Enterprise overlay —
 * which containerUpdateBlockedResponse() above already blocks
 * unconditionally in Docker. Activating one here anyway would leave a
 * customer's real license sitting on an instance that can never apply
 * it, no clearer sign anything's wrong than a quietly-missing "Check
 * for Overlay Updates" button later. Blocked up front instead, with a
 * concrete next step rather than a dead end.
 */
export function containerEnterpriseBlockedResponse(): NextResponse | null {
  if (!isContainerized()) return null;
  return NextResponse.json(
    {
      error:
        "Enterprise isn't available in the Docker deployment — applying the overlay needs sudo/systemd this container doesn't have. Enterprise on Docker requires its own Enterprise Docker image, built separately from Core's.",
      containerized: true,
    },
    { status: 409 }
  );
}
