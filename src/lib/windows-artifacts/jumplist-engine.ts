/**
 * Spawns the Windows Artifacts venv's python3 running jumplist-parse.py
 * against a single .automaticDestinations-ms file, parsing its JSON-lines
 * stdout protocol — same spawn/collect/timeout/discriminated-result
 * convention as lnk-engine.ts/prefetch-engine.ts/registry-engine.ts.
 */
import { spawn } from "child_process";
import path from "path";
import { parseParserLine } from "./parser-line";

export interface JumpListEntryRow {
  streamNumber: string;
  targetPath: string | null;
  arguments: string | null;
  workingDirectory: string | null;
  lastAccessed: string | null;
  accessRank: number | null;
  pinned: boolean | null;
  machineName: string | null;
}

export type JumpListParseResult =
  | { status: "ok"; entries: JumpListEntryRow[]; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 2 * 60;

export async function runJumpListParse(
  pythonPath: string,
  filePath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<JumpListParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "jumplist-parse.py");

  return new Promise<JumpListParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, filePath], { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: JumpListParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run jumplist-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      const entries: JumpListEntryRow[] = [];
      const scriptErrors: string[] = [];
      let notInstalled = false;

      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let obj: Record<string, unknown>;
        try { obj = parseParserLine(trimmed); } catch { continue; }

        switch (obj.type) {
          case "not_installed":
            notInstalled = true;
            break;
          case "jumplist_entry":
            entries.push({
              streamNumber: String(obj.stream_number ?? ""),
              targetPath: obj.target_path != null ? String(obj.target_path) : null,
              arguments: obj.arguments != null ? String(obj.arguments) : null,
              workingDirectory: obj.working_directory != null ? String(obj.working_directory) : null,
              lastAccessed: obj.last_accessed != null ? String(obj.last_accessed) : null,
              accessRank: obj.access_rank != null ? Number(obj.access_rank) : null,
              pinned: typeof obj.pinned === "boolean" ? obj.pinned : null,
              machineName: obj.machine_name != null ? String(obj.machine_name) : null,
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
        settle({ status: "error", message: detail || `jumplist-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", entries, scriptErrors });
    });
  });
}
