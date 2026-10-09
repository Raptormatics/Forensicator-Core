/**
 * Shared "kick off the privileged installer" logic, used by both the
 * offline (uploaded file) and online (downloaded from the update server)
 * install routes. Writes the audit trail, then spawns
 * deploy/forensicator-update.sh via the scoped sudoers rule and returns
 * immediately — the installer will restart the very process handling the
 * request, so callers must not await anything after this.
 */
import { spawn } from "child_process";
import { prisma } from "@/lib/db/prisma";
import { UPDATE_SCRIPT } from "./paths";

export type InstallSource = "offline" | "online";

export async function startInstall(opts: {
  packagePath: string;
  allowDowngrade: boolean;
  source: InstallSource;
  actor: { id: string; email: string };
  actorIp: string | null;
  metadata?: Record<string, unknown>;
}): Promise<void> {
  await prisma.auditLog.create({
    data: {
      actorId: opts.actor.id,
      actorEmail: opts.actor.email,
      actorIp: opts.actorIp,
      action: "update_started",
      resourceType: "system",
      result: "success",
      severity: "warning",
      metadata: { source: opts.source, allowDowngrade: opts.allowDowngrade, ...opts.metadata } as never,
    },
  });

  const args = ["--package", opts.packagePath, ...(opts.allowDowngrade ? ["--allow-downgrade"] : [])];
  const child = spawn("sudo", [UPDATE_SCRIPT, ...args], { detached: true, stdio: "ignore" });
  // Without this, a spawn-level failure (e.g. missing sudo binary) emits an
  // unhandled "error" event, which crashes the whole Node process.
  child.on("error", (err) => console.error("[updates] failed to spawn installer:", err));
  child.unref();
}

/**
 * Same shape as startInstall(), for the one operation that isn't a
 * version bump: turning this Core instance into Enterprise. Separate
 * function (not an InstallSource variant) because the audit action and
 * installer flag genuinely differ — forensicator-update.sh's --overlay
 * mode verifies against a different public key and does two things a
 * regular install never does (seeds LicenseStatus, writes the
 * enterprise-overlay-applied marker). Requires an already-activated
 * license — see src/lib/license/activation.ts — checked by the caller
 * before this is ever reached, not re-checked here.
 */
export async function startOverlayInstall(opts: {
  packagePath: string;
  actor: { id: string; email: string };
  actorIp: string | null;
  metadata?: Record<string, unknown>;
}): Promise<void> {
  await prisma.auditLog.create({
    data: {
      actorId: opts.actor.id,
      actorEmail: opts.actor.email,
      actorIp: opts.actorIp,
      action: "enterprise_overlay_started",
      resourceType: "system",
      result: "success",
      severity: "warning",
      metadata: { ...opts.metadata } as never,
    },
  });

  const child = spawn("sudo", [UPDATE_SCRIPT, "--overlay", opts.packagePath], { detached: true, stdio: "ignore" });
  child.on("error", (err) => console.error("[updates] failed to spawn overlay installer:", err));
  child.unref();
}

export function actorIp(headers: Headers): string | null {
  return headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? headers.get("x-real-ip") ?? null;
}
