/**
 * Shared filesystem paths for the update system, used by the admin API
 * routes. The actual privileged work happens in deploy/forensicator-update.sh
 * (run via a scoped sudoers rule) — these routes only read its output and
 * kick it off; they never touch the DB/app files directly.
 */
import fs from "fs";
import path from "path";

export const APP_DIR = process.cwd();
export const BACKUPS_DIR = path.join(APP_DIR, "backups");
export const PROGRESS_FILE = path.join(BACKUPS_DIR, ".current-progress.json");
export const UPDATE_SCRIPT = path.join(APP_DIR, "deploy", "forensicator-update.sh");

export function readJsonSafe<T>(filePath: string): T | null {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
  } catch {
    return null;
  }
}

export function installedVersion(): string {
  const pkg = readJsonSafe<{ version: string }>(path.join(APP_DIR, "package.json"));
  return pkg?.version ?? "unknown";
}

export type BackupManifest = {
  id: string;
  reason: string;
  fromVersion: string;
  toVersion: string;
  createdAt: string;
};

export type UpdateResult = {
  success: boolean;
  toVersion: string;
  fromVersion: string;
  backupId: string;
  rolledBack: boolean;
  error: string | null;
  completedAt: string;
};

export type BackupEntry = { manifest: BackupManifest; result: UpdateResult | null };

export function listBackups(): BackupEntry[] {
  if (!fs.existsSync(BACKUPS_DIR)) return [];

  const entries = fs
    .readdirSync(BACKUPS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => {
      const dir = path.join(BACKUPS_DIR, d.name);
      const manifest = readJsonSafe<BackupManifest>(path.join(dir, "backup-manifest.json"));
      const result = readJsonSafe<UpdateResult>(path.join(dir, "result.json"));
      return manifest ? { manifest, result } : null;
    })
    .filter((e): e is BackupEntry => e !== null);

  // Backup ids are UTC timestamps (YYYYMMDDTHHMMSSZ) — string-sortable.
  return entries.sort((a, b) => b.manifest.id.localeCompare(a.manifest.id));
}

type ProgressFile = { stage: string; message: string; updatedAt: string; pid?: number };

// The installer writes its own pid into the progress file on every stage
// change (deploy/forensicator-update.sh's set_progress) and removes the
// file on every terminal outcome (clear_progress) — so under normal
// operation, a progress file existing means an install is genuinely
// running right now. But it can only clean up after itself if it's still
// alive to do so: if it's killed outright (the cgroup-kill bug this
// replaced, an OOM-kill, a host reboot mid-build) the file is orphaned at
// whatever stage it died on, and every install/rollback route treats its
// mere existence as "already in progress" forever, permanently blocking
// all future update attempts with no way to recover short of a shell on
// the box. Detecting a dead pid here — the one place every caller already
// goes through — self-heals that without needing any of them to know about it.
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // The kernel checks existence before permission, so ESRCH ("no such
    // process") is the only error that actually proves the pid is gone.
    // Anything else — notably EPERM, which is what we get checking on
    // forensicator-update.sh (it runs as root via sudo, this app runs as
    // the unprivileged service user) — proves the opposite: the process
    // exists, we just can't signal it. Treating that as "dead" was the
    // bug: it falsely reaped every install the moment the freshly
    // restarted app polled while the still-running installer was still
    // on its last few cleanup lines.
    return (err as NodeJS.ErrnoException)?.code !== "ESRCH";
  }
}

function reapAbandonedProgress(progress: ProgressFile): void {
  const dangling = listBackups().find((b) => !b.result);
  if (dangling) {
    const result: UpdateResult = {
      success: false,
      toVersion: dangling.manifest.toVersion,
      fromVersion: dangling.manifest.fromVersion,
      backupId: dangling.manifest.id,
      rolledBack: false,
      error: `Installer process was interrupted while "${progress.message}" and never completed — no automatic rollback ran. Application files/database were only modified if progress had reached the "Installing new release" stage or later; check the app's running version to confirm.`,
      completedAt: new Date().toISOString(),
    };
    fs.writeFileSync(path.join(BACKUPS_DIR, dangling.manifest.id, "result.json"), JSON.stringify(result, null, 2));
  }
  fs.rmSync(PROGRESS_FILE, { force: true });
}

export function currentProgress(): ProgressFile | null {
  const progress = readJsonSafe<ProgressFile>(PROGRESS_FILE);
  if (!progress) return null;
  if (typeof progress.pid === "number" && !isAlive(progress.pid)) {
    reapAbandonedProgress(progress);
    return null;
  }
  return progress;
}
