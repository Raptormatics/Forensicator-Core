/**
 * Spawns the system python3 (with pyfsntfs/libfsntfs installed — see
 * getWinArtifactsSystemPythonPath()) running mft-parse.py against a
 * single standalone $MFT file, parsing its JSON-lines stdout protocol —
 * same spawn/collect/timeout/discriminated-result convention as
 * prefetch-engine.ts/registry-engine.ts.
 *
 * Unlike those two (a handful to a few thousand lines), a real $MFT can
 * emit hundreds of thousands to low millions of JSON lines — stdout is
 * consumed via `readline` as it arrives rather than buffered into one
 * giant string and split at the end, to avoid holding two copies (raw
 * text + split array) of a potentially very large payload in memory at
 * once. The parsed entries themselves are still accumulated into one
 * array and handed back in full — processor.ts is responsible for
 * batching the actual DB inserts.
 */
import { spawn } from "child_process";
import path from "path";
import readline from "readline";

export interface MftEntryRow {
  mftEntryNumber: number;
  sequenceNumber: number | null;
  name: string;
  path: string | null;
  parentEntryNumber: number | null;
  isAllocated: boolean;
  isDirectory: boolean;
  creationTime: string | null;
  modificationTime: string | null;
  accessTime: string | null;
  entryModificationTime: string | null;
  fileSize: string | null; // stringified — can exceed Number.MAX_SAFE_INTEGER for sparse/huge files
  hasAlternateDataStreams: boolean;
}

export type MftParseResult =
  | { status: "ok"; entries: MftEntryRow[]; entryCount: number; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

// A real $MFT can be enormous (low millions of entries) — this is a
// fundamentally different scale than every other artifact type's
// 60s-5min timeouts, sized generously rather than against a specific
// measured throughput figure (none was available to measure against in
// this environment — revisit against real-world timing once this has
// run against genuine large $MFT files).
const DEFAULT_TIMEOUT_SECONDS = 30 * 60;

export async function runMftParse(
  pythonPath: string,
  mftPath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<MftParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "mft-parse.py");

  return new Promise<MftParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, mftPath], { stdio: ["ignore", "pipe", "pipe"] });

    const entries: MftEntryRow[] = [];
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

    const settle = (result: MftParseResult) => {
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
      try { obj = JSON.parse(trimmed); } catch { return; }

      switch (obj.type) {
        case "not_installed":
          notInstalled = true;
          break;
        case "mft_entry":
          entries.push({
            mftEntryNumber: Number(obj.mft_entry_number ?? 0),
            sequenceNumber: obj.sequence_number != null ? Number(obj.sequence_number) : null,
            name: String(obj.name ?? ""),
            path: obj.path != null ? String(obj.path) : null,
            parentEntryNumber: obj.parent_entry_number != null ? Number(obj.parent_entry_number) : null,
            isAllocated: Boolean(obj.is_allocated),
            isDirectory: Boolean(obj.is_directory),
            creationTime: obj.creation_time ? String(obj.creation_time) : null,
            modificationTime: obj.modification_time ? String(obj.modification_time) : null,
            accessTime: obj.access_time ? String(obj.access_time) : null,
            entryModificationTime: obj.entry_modification_time ? String(obj.entry_modification_time) : null,
            fileSize: obj.file_size != null ? String(obj.file_size) : null,
            hasAlternateDataStreams: Boolean(obj.has_alternate_data_streams),
          });
          break;
        case "error":
          scriptErrors.push(String(obj.message));
          break;
      }
    });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run mft-parse.py ("${pythonPath}"): ${err.message}` });
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
        settle({ status: "error", message: detail || `mft-parse.py exited with code ${exitCode}${gotAnyLine ? "" : " (no output)"}` });
        return;
      }

      settle({ status: "ok", entries, entryCount: entries.length, scriptErrors });
    });
  });
}
