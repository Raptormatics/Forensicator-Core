/**
 * Spawns the Windows Artifacts venv's python3 (stdlib sqlite3 only — no
 * new dependency) running notification-parse.py against a single
 * wpndatabase.db/appdb.dat file, parsing its JSON-lines stdout protocol —
 * same convention as jumplist-engine.ts.
 */
import { spawn } from "child_process";
import path from "path";

export interface NotificationRow {
  arrivalTime: string | null;
  expiryTime: string | null;
  notifType: string | null;
  tag: string | null;
  groupName: string | null;
  handlerId: string | null;
  handlerLabel: string | null;
  payload: string | null;
  details: Record<string, unknown>;
}

export type NotificationParseResult =
  | { status: "ok"; entries: NotificationRow[]; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 120;

export async function runNotificationParse(
  pythonPath: string,
  filePath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<NotificationParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "notification-parse.py");

  return new Promise<NotificationParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, filePath], { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: NotificationParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run notification-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      const entries: NotificationRow[] = [];
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
          case "notification_entry":
            entries.push({
              arrivalTime: obj.arrival_time != null ? String(obj.arrival_time) : null,
              expiryTime: obj.expiry_time != null ? String(obj.expiry_time) : null,
              notifType: obj.notif_type != null ? String(obj.notif_type) : null,
              tag: obj.tag != null ? String(obj.tag) : null,
              groupName: obj.group_name != null ? String(obj.group_name) : null,
              handlerId: obj.handler_id != null ? String(obj.handler_id) : null,
              handlerLabel: obj.handler_label != null ? String(obj.handler_label) : null,
              payload: obj.payload != null ? String(obj.payload) : null,
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
        settle({ status: "error", message: detail || `notification-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", entries, scriptErrors });
    });
  });
}
