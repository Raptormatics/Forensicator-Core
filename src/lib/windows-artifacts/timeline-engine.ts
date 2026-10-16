/**
 * Spawns the Windows Artifacts venv's python3 (stdlib sqlite3 only — no
 * new dependency) running timeline-parse.py against a single
 * ActivitiesCache.db file, parsing its JSON-lines stdout protocol — same
 * convention as notification-engine.ts.
 */
import { spawn } from "child_process";
import path from "path";

export interface TimelineEntryRow {
  startTime: string | null;
  activityKind: string;
  appDisplayName: string | null;
  description: string | null;
  packageIdentifier: string | null;
  activeDurationSeconds: number | null;
  reportingApp: string | null;
  details: Record<string, unknown>;
}

export type TimelineParseResult =
  | { status: "ok"; entries: TimelineEntryRow[]; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 120;

export async function runTimelineParse(
  pythonPath: string,
  filePath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<TimelineParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "timeline-parse.py");

  return new Promise<TimelineParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, filePath], { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: TimelineParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run timeline-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      const entries: TimelineEntryRow[] = [];
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
          case "timeline_entry":
            entries.push({
              startTime: obj.start_time != null ? String(obj.start_time) : null,
              activityKind: String(obj.activity_kind ?? "unknown"),
              appDisplayName: obj.app_display_name != null ? String(obj.app_display_name) : null,
              description: obj.description != null ? String(obj.description) : null,
              packageIdentifier: obj.package_identifier != null ? String(obj.package_identifier) : null,
              activeDurationSeconds: obj.active_duration_seconds != null ? Number(obj.active_duration_seconds) : null,
              reportingApp: obj.reporting_app != null ? String(obj.reporting_app) : null,
              details: typeof obj.details === "object" && obj.details !== null ? (obj.details as Record<string, unknown>) : {},
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
        settle({ status: "error", message: detail || `timeline-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", entries, scriptErrors });
    });
  });
}
