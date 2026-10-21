/**
 * Spawns the system python3 (with pyesedb/libesedb installed — see
 * getWinArtifactsSystemPythonPath()) running srum-parse.py against a
 * single SRUDB.dat file, parsing its JSON-lines stdout protocol — same
 * spawn/collect/timeout/discriminated-result convention as every other
 * engine in this feature. Row counts here are modest (hundreds to
 * low-thousands, one row per app/timestamp bucket per table) — far
 * closer to registry-engine.ts's scale than mft-engine.ts's, so this
 * buffers the whole output rather than using readline.
 */
import { spawn } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { randomUUID } from "crypto";
import { parseParserLine } from "./parser-line";

export interface SrumEntryRow {
  tableName: string;
  providerLabel: string | null;
  timestamp: string | null;
  appId: string | null;
  userSid: string | null;
  details: Record<string, unknown>;
  registryConfirmed: boolean | null;
}

export type SrumParseResult =
  | { status: "ok"; entries: SrumEntryRow[]; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 5 * 60; // same tier as registry hives — SRUDB.dat is typically a few MB to tens of MB

/**
 * `extensionsMap`, when provided (WindowsArtifactUpload.srumExtensionsMap
 * from an already-processed software_hive file in the same collection),
 * is written to a throwaway temp JSON file and passed as srum-parse.py's
 * optional second argument — used only to flag whether a table's GUID is
 * confirmed present in this specific system's registry, not as the
 * provider-label source (see that script's own header comment).
 */
export async function runSrumParse(
  pythonPath: string,
  srudbPath: string,
  extensionsMap: Record<string, string> | null,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<SrumParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "srum-parse.py");

  let extensionsMapPath: string | null = null;
  if (extensionsMap && Object.keys(extensionsMap).length > 0) {
    extensionsMapPath = path.join(os.tmpdir(), `srum-extensions-${randomUUID()}.json`);
    try {
      fs.writeFileSync(extensionsMapPath, JSON.stringify(extensionsMap));
    } catch {
      extensionsMapPath = null;
    }
  }

  const args = [scriptPath, srudbPath];
  if (extensionsMapPath) args.push(extensionsMapPath);

  return new Promise<SrumParseResult>((resolve) => {
    const child = spawn(pythonPath, args, { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const cleanup = () => {
      if (extensionsMapPath) {
        try { fs.unlinkSync(extensionsMapPath); } catch { /* best-effort */ }
      }
    };

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: SrumParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      cleanup();
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run srum-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      const entries: SrumEntryRow[] = [];
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
          case "srum_entry":
            entries.push({
              tableName: String(obj.table_name ?? ""),
              providerLabel: obj.provider_label != null ? String(obj.provider_label) : null,
              timestamp: obj.timestamp ? String(obj.timestamp) : null,
              appId: obj.app_id != null ? String(obj.app_id) : null,
              userSid: obj.user_sid != null ? String(obj.user_sid) : null,
              details: (obj.details as Record<string, unknown>) ?? {},
              registryConfirmed: typeof obj.registry_confirmed === "boolean" ? obj.registry_confirmed : null,
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
        settle({ status: "error", message: detail || `srum-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", entries, scriptErrors });
    });
  });
}
