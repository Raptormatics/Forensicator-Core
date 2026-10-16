/**
 * Spawns the Windows Artifacts venv's python3 (with the pure-Python
 * `minidump` package installed — MIT licensed, no C deps) running
 * wer-dump-parse.py against a single .dmp file, parsing its JSON-lines
 * stdout protocol — same convention as prefetch-engine.ts (one entry per
 * file).
 */
import { spawn } from "child_process";
import path from "path";

export interface WerDumpModuleRow {
  name: string;
  baseAddress: string;
  size: number;
}

export interface WerDumpRow {
  exceptionCode: string | null;
  exceptionAddress: string | null;
  faultingThreadId: number | null;
  processId: number | null;
  processCreateTime: string | null;
  osVersion: string | null;
  cpuArchitecture: string | null;
  moduleList: WerDumpModuleRow[];
  miscInfo: Record<string, unknown>;
}

export type WerDumpParseResult =
  | { status: "ok"; entry: WerDumpRow | null; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 3 * 60; // a minidump is usually a few MB, well-structured streams — generous but not RAM-dump-scale

export async function runWerDumpParse(
  pythonPath: string,
  dumpPath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<WerDumpParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "wer-dump-parse.py");

  return new Promise<WerDumpParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, dumpPath], { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: WerDumpParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run wer-dump-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      let entry: WerDumpRow | null = null;
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
          case "wer_dump":
            entry = {
              exceptionCode: obj.exception_code != null ? String(obj.exception_code) : null,
              exceptionAddress: obj.exception_address != null ? String(obj.exception_address) : null,
              faultingThreadId: obj.faulting_thread_id != null ? Number(obj.faulting_thread_id) : null,
              processId: obj.process_id != null ? Number(obj.process_id) : null,
              processCreateTime: obj.process_create_time != null ? String(obj.process_create_time) : null,
              osVersion: obj.os_version != null ? String(obj.os_version) : null,
              cpuArchitecture: obj.cpu_architecture != null ? String(obj.cpu_architecture) : null,
              moduleList: Array.isArray(obj.module_list)
                ? obj.module_list.map((m) => {
                    const row = m as Record<string, unknown>;
                    return { name: String(row.name ?? ""), baseAddress: String(row.base_address ?? ""), size: Number(row.size ?? 0) };
                  })
                : [],
              miscInfo: typeof obj.misc_info === "object" && obj.misc_info !== null ? (obj.misc_info as Record<string, unknown>) : {},
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
        settle({ status: "error", message: detail || `wer-dump-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", entry, scriptErrors });
    });
  });
}
