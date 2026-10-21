/**
 * Spawns the system python3 (with pyesedb/libesedb installed — the same
 * dependency SRUM already uses) running search-parse.py against a single
 * Windows.edb/Windows.db file, parsing its JSON-lines stdout protocol.
 * Real-world column names are frequently per-install-specific/obfuscated,
 * so this is a structural table/row dump, not a semantic decode.
 *
 * Windows Search can realistically index hundreds of thousands of files,
 * so stdout is consumed via `readline` as it arrives rather than buffered
 * into one string first — same "potentially huge" precedent as
 * mft-engine.ts, even though this is a flat table scan rather than a
 * recursive walk.
 */
import { spawn } from "child_process";
import path from "path";
import readline from "readline";
import { parseParserLine } from "./parser-line";

export interface SearchIndexRow {
  tableName: string;
  recordIndex: number;
  details: Record<string, unknown>;
}

export type SearchIndexParseResult =
  | { status: "ok"; entries: SearchIndexRow[]; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 10 * 60;

export async function runSearchIndexParse(
  pythonPath: string,
  edbPath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<SearchIndexParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "search-parse.py");

  return new Promise<SearchIndexParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, edbPath], { stdio: ["ignore", "pipe", "pipe"] });

    const entries: SearchIndexRow[] = [];
    const scriptErrors: string[] = [];
    let notInstalled = false;
    let stderr = "";
    let timedOut = false;
    let settled = false;
    let gotAnyLine = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: SearchIndexParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    const rl = readline.createInterface({ input: child.stdout });
    rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      gotAnyLine = true;
      let obj: Record<string, unknown>;
      try { obj = parseParserLine(trimmed); } catch { return; }

      switch (obj.type) {
        case "not_installed":
          notInstalled = true;
          break;
        case "search_entry":
          entries.push({
            tableName: String(obj.table_name ?? ""),
            recordIndex: Number(obj.record_index ?? 0),
            details: typeof obj.details === "object" && obj.details !== null ? (obj.details as Record<string, unknown>) : {},
          });
          break;
        case "error":
          scriptErrors.push(String(obj.message));
          break;
      }
    });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run search-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      rl.close();
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }
      if (notInstalled) { settle({ status: "not_installed" }); return; }

      if (exitCode !== 0 && entries.length === 0) {
        const detail = (stderr || scriptErrors.join("; ")).trim().slice(0, 500);
        settle({ status: "error", message: detail || `search-parse.py exited with code ${exitCode}${gotAnyLine ? "" : " (no output)"}` });
        return;
      }

      settle({ status: "ok", entries, scriptErrors });
    });
  });
}
