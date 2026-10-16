/**
 * Spawns the Windows Artifacts venv's python3 (with the MIT-licensed
 * bits_parser package installed — pure Python, used as a library, not via
 * its CLI) running bits-parse.py against a single qmgr0.dat/qmgr1.dat
 * file, parsing its JSON-lines stdout protocol — same convention as
 * jumplist-engine.ts. One row per (job, file-transfer) pair; isCarved
 * marks a job recovered via carving (e.g. a deleted job record) rather
 * than clean parsing.
 */
import { spawn } from "child_process";
import path from "path";

export interface BitsJobRow {
  jobId: string | null;
  name: string | null;
  desc: string | null;
  cmd: string | null;
  sid: string | null;
  jobType: string | null;
  priority: string | null;
  state: string | null;
  ctime: string | null;
  mtime: string | null;
  destFn: string | null;
  srcFn: string | null;
  tmpFn: string | null;
  downloadSizeBytes: string | null;
  transferSizeBytes: string | null;
  isCarved: boolean;
}

export type BitsParseResult =
  | { status: "ok"; entries: BitsJobRow[]; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 2 * 60;

export async function runBitsParse(
  pythonPath: string,
  filePath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<BitsParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "bits-parse.py");

  return new Promise<BitsParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, filePath], { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: BitsParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run bits-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      const entries: BitsJobRow[] = [];
      const scriptErrors: string[] = [];
      let notInstalled = false;

      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let obj: Record<string, unknown>;
        try { obj = JSON.parse(trimmed); } catch { continue; }

        switch (obj.type) {
          case "not_installed":
            notInstalled = true;
            break;
          case "bits_job":
            entries.push({
              jobId: obj.job_id != null ? String(obj.job_id) : null,
              name: obj.name != null ? String(obj.name) : null,
              desc: obj.desc != null ? String(obj.desc) : null,
              cmd: obj.cmd != null ? String(obj.cmd) : null,
              sid: obj.sid != null ? String(obj.sid) : null,
              jobType: obj.job_type != null ? String(obj.job_type) : null,
              priority: obj.priority != null ? String(obj.priority) : null,
              state: obj.state != null ? String(obj.state) : null,
              ctime: obj.ctime != null ? String(obj.ctime) : null,
              mtime: obj.mtime != null ? String(obj.mtime) : null,
              destFn: obj.dest_fn != null ? String(obj.dest_fn) : null,
              srcFn: obj.src_fn != null ? String(obj.src_fn) : null,
              tmpFn: obj.tmp_fn != null ? String(obj.tmp_fn) : null,
              downloadSizeBytes: obj.download_size_bytes != null ? String(obj.download_size_bytes) : null,
              transferSizeBytes: obj.transfer_size_bytes != null ? String(obj.transfer_size_bytes) : null,
              isCarved: Boolean(obj.is_carved),
            });
            break;
          case "error":
            scriptErrors.push(String(obj.message));
            break;
        }
      }

      if (notInstalled) { settle({ status: "not_installed" }); return; }

      if (exitCode !== 0 && entries.length === 0) {
        const detail = (stderr || scriptErrors.join("; ") || stdout).trim().slice(0, 500);
        settle({ status: "error", message: detail || `bits-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", entries, scriptErrors });
    });
  });
}
