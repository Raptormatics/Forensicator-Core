/**
 * Spawns the Windows Artifacts venv's python3 running lnk-parse.py against
 * a single .lnk file or .customDestinations-ms container, parsing its
 * JSON-lines stdout protocol — same spawn/collect/timeout/discriminated-
 * result convention as prefetch-engine.ts/registry-engine.ts.
 */
import { spawn } from "child_process";
import path from "path";

export type LnkRole = "lnk" | "jumplist_custom";

export interface LnkEntryRow {
  targetPath: string | null;
  arguments: string | null;
  workingDirectory: string | null;
  iconLocation: string | null;
  creationTime: string | null;
  accessTime: string | null;
  modificationTime: string | null;
  fileSize: number | null;
  driveSerialNumber: string | null;
  driveType: string | null;
  volumeLabel: string | null;
  netName: string | null;
  deviceName: string | null;
  machineId: string | null;
}

export type LnkParseResult =
  | { status: "ok"; entries: LnkEntryRow[]; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 2 * 60; // a single .lnk or one jumplist container is small

export async function runLnkParse(
  pythonPath: string,
  filePath: string,
  role: LnkRole,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<LnkParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "lnk-parse.py");

  return new Promise<LnkParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, filePath, role], { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: LnkParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run lnk-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      const entries: LnkEntryRow[] = [];
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
          case "lnk_entry":
            entries.push({
              targetPath: obj.target_path != null ? String(obj.target_path) : null,
              arguments: obj.arguments != null ? String(obj.arguments) : null,
              workingDirectory: obj.working_directory != null ? String(obj.working_directory) : null,
              iconLocation: obj.icon_location != null ? String(obj.icon_location) : null,
              creationTime: obj.creation_time != null ? String(obj.creation_time) : null,
              accessTime: obj.access_time != null ? String(obj.access_time) : null,
              modificationTime: obj.modification_time != null ? String(obj.modification_time) : null,
              fileSize: obj.file_size != null ? Number(obj.file_size) : null,
              driveSerialNumber: obj.drive_serial_number != null ? String(obj.drive_serial_number) : null,
              driveType: obj.drive_type != null ? String(obj.drive_type) : null,
              volumeLabel: obj.volume_label != null ? String(obj.volume_label) : null,
              netName: obj.net_name != null ? String(obj.net_name) : null,
              deviceName: obj.device_name != null ? String(obj.device_name) : null,
              machineId: obj.machine_id != null && obj.machine_id !== "" ? String(obj.machine_id) : null,
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
        settle({ status: "error", message: detail || `lnk-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", entries, scriptErrors });
    });
  });
}
