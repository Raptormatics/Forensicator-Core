/**
 * Per-process, in-memory state for chunked uploads — shared by RAM Analysis
 * (src/app/api/ram-analysis/uploads/chunked/**) and Windows Artifact
 * Analysis (src/app/api/windows-artifacts/uploads/staged/**). Safe because
 * this app runs as a single long-running `next start` process (not
 * serverless/multi-instance) — see deploy/systemd/forensicator.service.
 * Contains no RAM- or Windows-Artifacts-specific logic — every function is
 * keyed by a plain session/staged-file id string, so callers from either
 * feature share the same maps without collision as long as ids are UUIDs
 * (which both RamUploadSession and WindowsArtifactStagedFile use).
 *
 * Two maps, both keyed by the session/staged-file id:
 *   - hashes: the session's live running SHA-256, updated as chunks land.
 *     If the process restarts mid-session (KillMode=process is used
 *     deliberately so the Admin UI's self-update installer can restart this
 *     exact process — a designed-for occurrence, not a rare crash), the
 *     entry is gone; getOrRebuildHash() reconstructs it by re-hashing the
 *     .partial file's already-received bytes from disk rather than failing
 *     the session outright.
 *   - locks: a hand-rolled mutex (promise chain) serializing all chunk
 *     processing for a given session. Checking `offset === receivedBytes`
 *     is not race-safe on its own — two concurrent requests for the same
 *     correct offset can both pass the check before either updates state,
 *     double-counting receivedBytes and corrupting the hash even though the
 *     underlying positional file write stays correct. Every read-check-
 *     write-hash-update-DB-update sequence for a session must run inside
 *     withSessionLock().
 */
import fs from "fs";
import crypto from "crypto";

const hashes = new Map<string, crypto.Hash>();
const locks = new Map<string, Promise<void>>();

export function registerNewHash(sessionId: string): void {
  hashes.set(sessionId, crypto.createHash("sha256"));
}

export function getHash(sessionId: string): crypto.Hash | undefined {
  return hashes.get(sessionId);
}

export function deleteSessionState(sessionId: string): void {
  hashes.delete(sessionId);
  locks.delete(sessionId);
}

/** Runs `fn` exclusively for this session, queued behind any in-flight call for the same session. */
export function withSessionLock<T>(sessionId: string, fn: () => Promise<T>): Promise<T> {
  const previous = locks.get(sessionId) ?? Promise.resolve();
  let release!: () => void;
  const next = new Promise<void>((resolve) => { release = resolve; });
  locks.set(sessionId, previous.then(() => next));

  return previous.then(fn).finally(() => {
    release();
    // Avoid an ever-growing map for long-lived sessions with many chunks —
    // only drop our own link if nothing chained after it.
    if (locks.get(sessionId) === previous.then(() => next)) locks.delete(sessionId);
  });
}

/**
 * Returns the session's live hash, rebuilding it from disk if the in-memory
 * entry is missing (process restart mid-session). Rebuilding re-reads only
 * the bytes already confirmed received (`receivedBytes`), not the whole
 * (potentially still-growing) file.
 */
export async function getOrRebuildHash(sessionId: string, storagePath: string, receivedBytes: bigint): Promise<crypto.Hash> {
  const existing = hashes.get(sessionId);
  if (existing) return existing;

  const hash = crypto.createHash("sha256");
  if (receivedBytes > BigInt(0)) {
    await new Promise<void>((resolve, reject) => {
      const stream = fs.createReadStream(storagePath, { start: 0, end: Number(receivedBytes) - 1 });
      stream.on("data", (chunk) => hash.update(chunk));
      stream.on("end", resolve);
      stream.on("error", reject);
    });
  }
  hashes.set(sessionId, hash);
  return hash;
}
