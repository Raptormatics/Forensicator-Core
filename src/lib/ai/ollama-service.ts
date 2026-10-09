/**
 * Local Ollama service control — spawns deploy/forensicator-ollama-ctl.sh
 * via the scoped sudoers rule (see provision.sh), the same pattern as
 * src/lib/updates/install.ts + paths.ts use for the update installer.
 *
 * Only relevant when SystemSettings.ollamaManaged is true (Settings > AI
 * Analysis chose to run Ollama on this host rather than point at an
 * external instance) — model list/pull/delete work against any Ollama host
 * via plain HTTP and don't need this.
 */
import { spawn, execFile } from "child_process";
import { promisify } from "util";
import fs from "fs";
import path from "path";

const execFileAsync = promisify(execFile);

export const DATA_DIR = path.join(process.cwd(), "data");
export const OLLAMA_PROGRESS_FILE = path.join(DATA_DIR, ".ollama-progress.json");
export const OLLAMA_RESULT_FILE = path.join(DATA_DIR, ".ollama-last-result.json");
export const OLLAMA_CTL_SCRIPT = path.join(process.cwd(), "deploy", "forensicator-ollama-ctl.sh");

export type OllamaCtlAction = "install" | "uninstall" | "start" | "stop";

function readJsonSafe<T>(filePath: string): T | null {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
  } catch {
    return null;
  }
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

type ProgressFile = { stage: string; message: string; updatedAt: string; pid?: number };
export type OllamaResult = { success: boolean; action: string; message: string; completedAt: string };

/**
 * Same self-healing logic as updates/paths.ts's currentProgress(): if the
 * script died mid-run (killed, OOM, reboot) without reaching clear_progress,
 * a stale file would otherwise block every future action forever.
 */
export function ollamaProgress(): ProgressFile | null {
  const progress = readJsonSafe<ProgressFile>(OLLAMA_PROGRESS_FILE);
  if (!progress) return null;
  if (typeof progress.pid === "number" && !isAlive(progress.pid)) {
    fs.rmSync(OLLAMA_PROGRESS_FILE, { force: true });
    return null;
  }
  return progress;
}

export function ollamaLastResult(): OllamaResult | null {
  return readJsonSafe<OllamaResult>(OLLAMA_RESULT_FILE);
}

/**
 * Kicks off a privileged action (install/uninstall/start/stop) and returns
 * immediately — progress is polled via ollamaProgress()/ollamaLastResult(),
 * same convention as the update installer.
 */
export function startOllamaCtl(action: OllamaCtlAction, opts: { purgeModels?: boolean } = {}): void {
  const args = [OLLAMA_CTL_SCRIPT, action, ...(opts.purgeModels ? ["--purge-models"] : [])];
  const child = spawn("sudo", args, { detached: true, stdio: "ignore" });
  child.on("error", (err) => console.error("[ollama-service] failed to spawn ctl script:", err));
  child.unref();
}

/**
 * Synchronous status check — cheap enough (systemctl is-active + a version
 * flag) to run inline rather than through the progress-file mechanism.
 * Still needs sudo: `systemctl is-active` on an arbitrary unit and reading
 * whether the ollama binary/service exist are read-only but the script is
 * the only thing in the sudoers allow-list, so status goes through it too.
 */
export async function getOllamaCtlStatus(): Promise<{ installed: boolean; active: string; version: string | null }> {
  try {
    const { stdout } = await execFileAsync("sudo", [OLLAMA_CTL_SCRIPT, "status"], { timeout: 10_000 });
    const parsed = JSON.parse(stdout.trim());
    return { installed: !!parsed.installed, active: parsed.active ?? "unknown", version: parsed.version ?? null };
  } catch {
    return { installed: false, active: "unknown", version: null };
  }
}
