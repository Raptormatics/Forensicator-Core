/**
 * Spawns the Windows Artifacts venv's python3 running wer-parse.py against
 * a single Report.wer text file, parsing its JSON-lines stdout protocol —
 * same spawn/collect/timeout/discriminated-result convention as
 * prefetch-engine.ts (one entry per file).
 */
import { spawn } from "child_process";
import path from "path";

export interface WerReportRow {
  eventType: string | null;
  eventTime: string | null;
  reportGuid: string | null;
  appName: string | null;
  appVersion: string | null;
  appTimestamp: string | null;
  faultModuleName: string | null;
  faultModuleVersion: string | null;
  faultModuleTimestamp: string | null;
  exceptionCode: string | null;
  exceptionOffset: string | null;
  sigFields: { index: number; kind: "sig" | "dynamic_sig" | "ui"; name: string | null; value: string }[];
  rawFields: Record<string, string>;
}

export type WerReportParseResult =
  | { status: "ok"; entry: WerReportRow | null; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 60; // plain text file, tiny

export async function runWerReportParse(
  pythonPath: string,
  werPath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<WerReportParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "wer-parse.py");

  return new Promise<WerReportParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, werPath], { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: WerReportParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run wer-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      let entry: WerReportRow | null = null;
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
          case "wer_report":
            entry = {
              eventType: obj.event_type != null ? String(obj.event_type) : null,
              eventTime: obj.event_time != null ? String(obj.event_time) : null,
              reportGuid: obj.report_guid != null ? String(obj.report_guid) : null,
              appName: obj.app_name != null ? String(obj.app_name) : null,
              appVersion: obj.app_version != null ? String(obj.app_version) : null,
              appTimestamp: obj.app_timestamp != null ? String(obj.app_timestamp) : null,
              faultModuleName: obj.fault_module_name != null ? String(obj.fault_module_name) : null,
              faultModuleVersion: obj.fault_module_version != null ? String(obj.fault_module_version) : null,
              faultModuleTimestamp: obj.fault_module_timestamp != null ? String(obj.fault_module_timestamp) : null,
              exceptionCode: obj.exception_code != null ? String(obj.exception_code) : null,
              exceptionOffset: obj.exception_offset != null ? String(obj.exception_offset) : null,
              sigFields: Array.isArray(obj.sig_fields)
                ? obj.sig_fields.map((f) => {
                    const row = f as Record<string, unknown>;
                    return {
                      index: Number(row.index ?? 0),
                      kind: (row.kind === "dynamic_sig" || row.kind === "ui") ? row.kind : "sig",
                      name: row.name != null ? String(row.name) : null,
                      value: String(row.value ?? ""),
                    };
                  })
                : [],
              rawFields: typeof obj.raw_fields === "object" && obj.raw_fields !== null
                ? Object.fromEntries(Object.entries(obj.raw_fields as Record<string, unknown>).map(([k, v]) => [k, String(v)]))
                : {},
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
        settle({ status: "error", message: detail || `wer-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", entry, scriptErrors });
    });
  });
}
