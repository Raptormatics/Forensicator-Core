/**
 * Spawns the system python3 (with python3-libscca installed) running
 * prefetch-parse.py against a single .pf file, parsing its JSON-lines
 * stdout protocol — same spawn/collect/timeout/discriminated-result
 * convention as registry-engine.ts/src/lib/yara/engine.ts.
 */
import { spawn } from "child_process";
import path from "path";
import { parseParserLine } from "./parser-line";

export interface PrefetchEntryRow {
  executableName: string;
  runCount: number | null;
  lastRunTimes: string[];
  volumeSerials: string[];
  referencedFiles: string[];
}

export type PrefetchParseResult =
  | { status: "ok"; entry: PrefetchEntryRow | null; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 60; // a single .pf file is tiny — generous but not RAM-plugin-scale

export async function runPrefetchParse(
  pythonPath: string,
  pfPath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<PrefetchParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "prefetch-parse.py");

  return new Promise<PrefetchParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, pfPath], { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: PrefetchParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run prefetch-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      let entry: PrefetchEntryRow | null = null;
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
          case "entry":
            entry = {
              executableName: String(obj.executable_name ?? ""),
              runCount: obj.run_count != null ? Number(obj.run_count) : null,
              lastRunTimes: Array.isArray(obj.last_run_times) ? obj.last_run_times.map(String) : [],
              volumeSerials: Array.isArray(obj.volume_serials) ? obj.volume_serials.map(String) : [],
              referencedFiles: Array.isArray(obj.referenced_files) ? obj.referenced_files.map(String) : [],
            };
            break;
          case "error":
            scriptErrors.push(String(obj.message));
            break;
        }
      }

      if (notInstalled) { settle({ status: "not_installed" }); return; }

      if (exitCode !== 0 && !entry) {
        const detail = (stderr || scriptErrors.join("; ") || stdout).trim().slice(0, 500);
        settle({ status: "error", message: detail || `prefetch-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", entry, scriptErrors });
    });
  });
}
