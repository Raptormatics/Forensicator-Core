/**
 * Shared spawner for the Stage-2 Windows Artifact parsers (wmi-parse.py,
 * defender-history-parse.py, app-artifact-parse.py, logfile-parse.py,
 * payload-parse.py, search-sqlite-parse.py, bits-ese-parse.py). They all
 * speak the same JSON-lines protocol (forensicator_records.py) — generic
 * `record` rows for ArtifactRecordEntry, plus `search_entry`/`bits_job`
 * rows in exactly the shape search-parse.py/bits-parse.py already emit so
 * those land in the existing SearchIndexEntry/BitsJobEntry tables — so one
 * runner replaces a near-identical engine file per artifact type.
 *
 * Unlike the older engines, stdout is consumed line by line instead of
 * accumulated into one string: a Windows 11 Search property store or a
 * pagefile indicator sweep can emit hundreds of thousands of rows.
 */
import { spawn } from "child_process";
import path from "path";
import readline from "readline";
import type { BitsJobRow } from "./bits-engine";
import type { SearchIndexRow } from "./search-engine";
import { parseParserLine } from "./parser-line";

export interface ArtifactRecordRow {
  kind: string;
  title: string;
  timestamp: string | null;
  path: string | null;
  user: string | null;
  process: string | null;
  url: string | null;
  ip: string | null;
  sha256: string | null;
  sha1: string | null;
  md5: string | null;
  details: Record<string, unknown>;
}

export type RecordParseResult =
  | { status: "ok"; records: ArtifactRecordRow[]; searchEntries: SearchIndexRow[]; bitsJobs: BitsJobRow[]; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

// Postgres rejects U+0000 in TEXT and JSONB ("invalid byte sequence",
// 22021) — and these parsers read binary formats where a stray NUL in a
// decoded string is easy to miss. Strip it everywhere before insert.
const NUL = /\u0000/g;
const s = (v: unknown): string | null => (v == null || v === "" ? null : String(v).replace(NUL, ""));

function scrub(v: unknown): unknown {
  if (typeof v === "string") return v.replace(NUL, "");
  if (Array.isArray(v)) return v.map(scrub);
  if (v && typeof v === "object") {
    return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k.replace(NUL, ""), scrub(x)]));
  }
  return v;
}

export interface RecordParseOptions {
  /** When set, `search_entry` rows are handed over in batches of
   * `searchBatchSize` (and not kept in the result) — a Windows 11 Search
   * property store is tens of thousands of items with content snippets;
   * holding them all, plus their insert copies, helped OOM-kill the worker
   * on a 5 GB appliance. Reading pauses while the callback runs. */
  onSearchBatch?: (rows: SearchIndexRow[]) => Promise<void>;
  searchBatchSize?: number;
}

export async function runRecordParse(
  pythonPath: string,
  script: string,
  args: string[],
  timeoutSeconds: number,
  options: RecordParseOptions = {}
): Promise<RecordParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", script);
  const child = spawn(pythonPath, [scriptPath, ...args], { stdio: ["ignore", "pipe", "pipe"] });
  const records: ArtifactRecordRow[] = [];
  let searchEntries: SearchIndexRow[] = [];
  const bitsJobs: BitsJobRow[] = [];
  const scriptErrors: string[] = [];
  const batchSize = options.searchBatchSize ?? 2000;
  let streamedSearch = 0;
  let stderr = "";
  let notInstalled = false;
  let timedOut = false;

  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, (timeoutSeconds + 10) * 1000);
  child.stderr.on("data", (chunk) => { if (stderr.length < 20000) stderr += chunk.toString(); });
  const exited = new Promise<number | null>((resolve) => child.on("close", resolve));
  const spawnError = new Promise<Error>((resolve) => child.on("error", resolve));

  const handle = async (obj: Record<string, unknown>) => {
    switch (obj.type) {
      case "not_installed":
        notInstalled = true;
        break;
      case "record":
        records.push({
          kind: String(obj.kind ?? "unknown"),
          title: String(obj.title ?? "").replace(NUL, ""),
          timestamp: s(obj.timestamp),
          path: s(obj.path),
          user: s(obj.user),
          process: s(obj.process),
          url: s(obj.url),
          ip: s(obj.ip),
          sha256: s(obj.sha256),
          sha1: s(obj.sha1),
          md5: s(obj.md5),
          details: typeof obj.details === "object" && obj.details !== null ? (scrub(obj.details) as Record<string, unknown>) : {},
        });
        break;
      case "search_entry":
        searchEntries.push({
          tableName: String(obj.table_name ?? "").replace(NUL, ""),
          recordIndex: Number(obj.record_index ?? 0),
          details: typeof obj.details === "object" && obj.details !== null ? (scrub(obj.details) as Record<string, unknown>) : {},
        });
        if (options.onSearchBatch && searchEntries.length >= batchSize) {
          const batch = searchEntries;
          searchEntries = [];
          streamedSearch += batch.length;
          await options.onSearchBatch(batch);
        }
        break;
      case "bits_job":
        bitsJobs.push({
          jobId: s(obj.job_id), name: s(obj.name), desc: s(obj.desc), cmd: s(obj.cmd), sid: s(obj.sid),
          jobType: s(obj.job_type), priority: s(obj.priority), state: s(obj.state),
          ctime: s(obj.ctime), mtime: s(obj.mtime), destFn: s(obj.dest_fn), srcFn: s(obj.src_fn), tmpFn: s(obj.tmp_fn),
          downloadSizeBytes: s(obj.download_size_bytes), transferSizeBytes: s(obj.transfer_size_bytes),
          isCarved: Boolean(obj.is_carved),
        });
        break;
      case "error":
        if (scriptErrors.length < 500) scriptErrors.push(String(obj.message));
        break;
    }
  };

  try {
    const consume = (async () => {
      // for-await gives real backpressure: the child's stdout isn't read
      // further while a batch callback is inserting.
      for await (const line of readline.createInterface({ input: child.stdout })) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let obj: Record<string, unknown>;
        try { obj = parseParserLine(trimmed); } catch { continue; }
        await handle(obj);
      }
      if (options.onSearchBatch && searchEntries.length > 0) {
        streamedSearch += searchEntries.length;
        await options.onSearchBatch(searchEntries);
        searchEntries = [];
      }
    })();
    const outcome = await Promise.race([consume.then(() => null), spawnError]);
    if (outcome instanceof Error) return { status: "error", message: `Failed to run ${script} ("${pythonPath}"): ${outcome.message}` };
    const exitCode = await exited;
    if (timedOut) return { status: "timeout" };
    if (notInstalled) return { status: "not_installed" };
    const gotAnything = records.length > 0 || searchEntries.length > 0 || streamedSearch > 0 || bitsJobs.length > 0;
    if (exitCode !== 0 && !gotAnything) {
      const detail = (stderr || scriptErrors.join("; ")).trim().slice(0, 500);
      return { status: "error", message: detail || `${script} exited with code ${exitCode}` };
    }
    return { status: "ok", records, searchEntries, bitsJobs, scriptErrors };
  } catch (err) {
    child.kill("SIGKILL");
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
