/**
 * Spawns the Windows Artifacts venv's python3 running recyclebin-parse.py
 * against a single $I metadata file, parsing its JSON-lines stdout
 * protocol — same convention as jumplist-engine.ts. Each $I file yields
 * exactly one record, but the "one entry per line" shape is kept for
 * consistency with every other engine here.
 */
import { spawn } from "child_process";
import path from "path";

export interface RecycleBinRow {
  formatVersion: number;
  originalPath: string;
  deletedTime: string | null;
  fileSizeBytes: string | null;
}

export type RecycleBinParseResult =
  | { status: "ok"; entries: RecycleBinRow[]; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 30; // a single $I file is a few hundred bytes

export async function runRecycleBinParse(
  pythonPath: string,
  filePath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<RecycleBinParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "recyclebin-parse.py");

  return new Promise<RecycleBinParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, filePath], { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: RecycleBinParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run recyclebin-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      const entries: RecycleBinRow[] = [];
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
          case "recyclebin_entry":
            entries.push({
              formatVersion: Number(obj.format_version ?? 0),
              originalPath: String(obj.original_path ?? ""),
              deletedTime: obj.deleted_time != null ? String(obj.deleted_time) : null,
              fileSizeBytes: obj.file_size_bytes != null ? String(obj.file_size_bytes) : null,
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
        settle({ status: "error", message: detail || `recyclebin-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", entries, scriptErrors });
    });
  });
}
