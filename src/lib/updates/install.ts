/**
 * Shared "kick off the privileged installer" logic, used by both the
 * offline (uploaded file) and online (downloaded from the update server)
 * install routes. Writes the audit trail, then spawns
 * deploy/forensicator-update.sh via the scoped sudoers rule and returns
 * immediately — the installer will restart the very process handling the
 * request, so callers must not await anything after this.
 */
import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { prisma } from "@/lib/db/prisma";
import { UPDATE_SCRIPT, BACKUPS_DIR, listBackups } from "./paths";

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

/**
 * The *_started audit rows above are the only part of an update's
 * lifecycle this app can log synchronously — deploy/forensicator-update.sh
 * runs out-of-process (spawned detached, specifically to survive this
 * very process being restarted mid-install) and has no way to call back
 * in; its actual outcome only ever lands in <backup-dir>/result.json,
 * read by listBackups(). Without this, the Audit Log would show every
 * update as perpetually "started" and never record whether it actually
 * succeeded, failed, or was rolled back.
 *
 * Called from the status route, which the Admin UI polls every 2s while
 * any install is in flight — picks up a newly-resolved backup within one
 * poll of it finishing. Tracked via a small sentinel file next to
 * result.json (not a DB query) so this only ever fires once per backup,
 * consistent with how the rest of the update system already tracks state
 * on disk rather than in the database (progress file, result.json,
 * backup-manifest.json).
 *
 * No actorId — deliberately: this is the app noticing an outcome, not a
 * new action by anyone currently signed in. metadata.backupId lets anyone
 * cross-reference it against that update's own *_started row (which does
 * have the real actor) if needed.
 */
export async function recordCompletionAuditEvents(): Promise<void> {
  for (const { manifest, result } of listBackups()) {
    if (!result) continue;
    const sentinel = path.join(BACKUPS_DIR, manifest.id, ".audit-logged");
    if (fs.existsSync(sentinel)) continue;

    await prisma.auditLog.create({
      data: {
        action: result.success ? "update_completed" : "update_failed",
        resourceType: "system",
        result: result.success ? "success" : "failure",
        severity: result.success ? "info" : "critical",
        metadata: {
          backupId: manifest.id,
          reason: manifest.reason,
          fromVersion: manifest.fromVersion,
          toVersion: manifest.toVersion,
          rolledBack: result.rolledBack,
          error: result.error,
        } as never,
      },
    });
    // Best-effort — if this throws, the next poll just retries the write
    // (harmless duplicate rows beat losing the event entirely).
    try { fs.writeFileSync(sentinel, new Date().toISOString()); } catch { /* retried next poll */ }
  }
}
