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

const s = (v: unknown): string | null => (v == null || v === "" ? null : String(v));

export async function runRecordParse(
  pythonPath: string,
  script: string,
  args: string[],
  timeoutSeconds: number
): Promise<RecordParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", script);

  return new Promise<RecordParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    const records: ArtifactRecordRow[] = [];
    const searchEntries: SearchIndexRow[] = [];
    const bitsJobs: BitsJobRow[] = [];
    const scriptErrors: string[] = [];
    let stderr = "";
    let notInstalled = false;
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: RecordParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stderr.on("data", (chunk) => { if (stderr.length < 20000) stderr += chunk.toString(); });
    child.on("error", (err) => settle({ status: "error", message: `Failed to run ${script} ("${pythonPath}"): ${err.message}` }));

    const lines = readline.createInterface({ input: child.stdout });
    let linesClosed = false;
    lines.on("close", () => { linesClosed = true; });
    lines.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      let obj: Record<string, unknown>;
      try { obj = JSON.parse(trimmed); } catch { return; }
      switch (obj.type) {
        case "not_installed":
          notInstalled = true;
          break;
        case "record":
          records.push({
            kind: String(obj.kind ?? "unknown"),
            title: String(obj.title ?? ""),
            timestamp: s(obj.timestamp),
            path: s(obj.path),
            user: s(obj.user),
            process: s(obj.process),
            url: s(obj.url),
            ip: s(obj.ip),
            sha256: s(obj.sha256),
            sha1: s(obj.sha1),
            md5: s(obj.md5),
            details: typeof obj.details === "object" && obj.details !== null ? (obj.details as Record<string, unknown>) : {},
          });
          break;
        case "search_entry":
          searchEntries.push({
            tableName: String(obj.table_name ?? ""),
            recordIndex: Number(obj.record_index ?? 0),
            details: typeof obj.details === "object" && obj.details !== null ? (obj.details as Record<string, unknown>) : {},
          });
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
          scriptErrors.push(String(obj.message));
          break;
      }
    });

    child.on("close", (exitCode) => {
      // readline may still be draining when "close" fires on very fast
      // exits — wait for its own close before settling.
      const finish = () => {
        if (timedOut) return settle({ status: "timeout" });
        if (notInstalled) return settle({ status: "not_installed" });
        const gotAnything = records.length > 0 || searchEntries.length > 0 || bitsJobs.length > 0;
        if (exitCode !== 0 && !gotAnything) {
          const detail = (stderr || scriptErrors.join("; ")).trim().slice(0, 500);
          return settle({ status: "error", message: detail || `${script} exited with code ${exitCode}` });
        }
        settle({ status: "ok", records, searchEntries, bitsJobs, scriptErrors });
      };
      if (linesClosed) finish();
      else lines.once("close", finish);
    });
  });
}
