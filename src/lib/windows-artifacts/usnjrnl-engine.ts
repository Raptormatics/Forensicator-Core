/**
 * Spawns the Windows Artifacts venv's python3 running usnjrnl-parse.py
 * against a single standalone $UsnJrnl:$J stream file — pure stdlib
 * `struct` parsing (see that script's own header comment for why no
 * library is used), so unlike mft-engine.ts/srum-engine.ts this runs
 * under the venv, not a system-python C-linked-library path.
 *
 * Same spawn/collect/timeout/discriminated-result convention as every
 * other engine in this feature. $UsnJrnl:$J can also run into millions
 * of records — stdout is consumed via `readline` as it arrives rather
 * than buffered into one giant string, same reasoning as mft-engine.ts.
 */
import { spawn } from "child_process";
import path from "path";
import readline from "readline";
import { parseParserLine } from "./parser-line";

export interface UsnJrnlEntryRow {
  usn: string; // stringified — can exceed Number.MAX_SAFE_INTEGER
  fileReferenceNumber: string;
  parentFileReferenceNumber: string;
  timestamp: string | null;
  reason: string[];
  fileName: string | null;
  fileAttributes: number | null;
  sourceInfo: number | null;
}

export type UsnJrnlParseResult =
  | { status: "ok"; entries: UsnJrnlEntryRow[]; entryCount: number; scriptErrors: string[] }
  | { status: "not_installed" } // kept for shape consistency with the other engines — this script has no import to fail on, so this never actually fires
  | { status: "timeout" }
  | { status: "error"; message: string };

// Same reasoning as mft-engine.ts — a real $UsnJrnl:$J can hold millions
// of records, far beyond every other artifact type's 60s-5min timeouts.
const DEFAULT_TIMEOUT_SECONDS = 30 * 60;

export async function runUsnJrnlParse(
  pythonPath: string,
  jStreamPath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<UsnJrnlParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "usnjrnl-parse.py");

  return new Promise<UsnJrnlParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, jStreamPath], { stdio: ["ignore", "pipe", "pipe"] });

    const entries: UsnJrnlEntryRow[] = [];
    const scriptErrors: string[] = [];
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: UsnJrnlParseResult) => {
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
      let obj: Record<string, unknown>;
      try { obj = parseParserLine(trimmed); } catch { return; }

      switch (obj.type) {
        case "usn_entry":
          entries.push({
            usn: String(obj.usn ?? "0"),
            fileReferenceNumber: String(obj.file_reference_number ?? "0"),
            parentFileReferenceNumber: String(obj.parent_file_reference_number ?? "0"),
            timestamp: obj.timestamp ? String(obj.timestamp) : null,
            reason: Array.isArray(obj.reason) ? obj.reason.map(String) : [],
            fileName: obj.file_name != null ? String(obj.file_name) : null,
            fileAttributes: obj.file_attributes != null ? Number(obj.file_attributes) : null,
            sourceInfo: obj.source_info != null ? Number(obj.source_info) : null,
          });
          break;
        case "error":
          scriptErrors.push(String(obj.message));
          break;
      }
    });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run usnjrnl-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      rl.close();
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      if (exitCode !== 0 && entries.length === 0) {
        const detail = (stderr || scriptErrors.join("; ")).trim().slice(0, 500);
        settle({ status: "error", message: detail || `usnjrnl-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", entries, entryCount: entries.length, scriptErrors });
    });
  });
}
