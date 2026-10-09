/**
 * In-process model pull manager. Unlike ollama-service.ts's install/start/
 * stop actions, pulling a model needs no privilege at all — it's a plain
 * HTTP call to whatever Ollama host is configured (local or remote); Ollama
 * itself owns the actual download. This just runs that call in the
 * background (so the triggering API request can return immediately) and
 * persists progress to a file the client polls, matching the same
 * poll-a-status-endpoint convention the update system uses.
 */
import fs from "fs";
import path from "path";
import { ollamaPullModel } from "./ollama";

const DATA_DIR = path.join(process.cwd(), "data");
const PULL_STATUS_FILE = path.join(DATA_DIR, ".ollama-pull-status.json");

export type PullStatus = {
  model: string;
  status: string;
  completed: number;
  total: number;
  startedAt: string;
  updatedAt: string;
  done: boolean;
  error: string | null;
};

// Tracks the in-flight pull for THIS process. Naturally resets to null on
// restart — currentPullStatus() below reconciles a stale on-disk "done:
// false" against that so a restart mid-pull doesn't wedge the UI forever.
let activePull: { model: string; promise: Promise<void> } | null = null;

function writeStatus(status: PullStatus): void {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(PULL_STATUS_FILE, JSON.stringify(status, null, 2));
}

function readStatus(): PullStatus | null {
  try {
    return JSON.parse(fs.readFileSync(PULL_STATUS_FILE, "utf8")) as PullStatus;
  } catch {
    return null;
  }
}

export function isPulling(): boolean {
  return activePull !== null;
}

/** What model, if any, is actively pulling in this process right now. */
export function activePullModel(): string | null {
  return activePull?.model ?? null;
}

export function currentPullStatus(): PullStatus | null {
  const status = readStatus();
  if (!status) return null;
  if (!status.done && !isPulling()) {
    // On-disk state claims a pull is running, but this process has no
    // matching in-flight promise — it was interrupted (server restart,
    // crash) rather than actually still running. Reconcile rather than
    // leaving the UI stuck on "downloading" forever.
    const reconciled: PullStatus = {
      ...status,
      done: true,
      error: "Pull was interrupted (server restarted or crashed) before it finished.",
      updatedAt: new Date().toISOString(),
    };
    writeStatus(reconciled);
    return reconciled;
  }
  return status;
}

/**
 * Starts a pull in the background and returns immediately. Throws
 * synchronously if a pull is already active — callers should check
 * isPulling() first to give a friendlier error, this is the hard guard.
 */
export function startModelPull(host: string, model: string): void {
  if (activePull) {
    throw new Error(`A pull for "${activePull.model}" is already in progress.`);
  }

  const status: PullStatus = {
    model,
    status: "starting",
    completed: 0,
    total: 0,
    startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    done: false,
    error: null,
  };
  writeStatus(status);

  const promise = (async () => {
    try {
      await ollamaPullModel(host, model, (progress) => {
        status.status = progress.status;
        if (typeof progress.completed === "number") status.completed = progress.completed;
        if (typeof progress.total === "number") status.total = progress.total;
        status.updatedAt = new Date().toISOString();
        writeStatus(status);
      });
      status.status = "success";
      status.done = true;
      status.updatedAt = new Date().toISOString();
      writeStatus(status);
    } catch (err) {
      status.done = true;
      status.error = err instanceof Error ? err.message : "Unknown error";
      status.updatedAt = new Date().toISOString();
      writeStatus(status);
    } finally {
      activePull = null;
    }
  })();

  activePull = { model, promise };
}

export function clearPullStatus(): void {
  fs.rmSync(PULL_STATUS_FILE, { force: true });
}
