/**
 * Runs custom Yara rules directly against a raw memory image via
 * yara-scan.py, using the Volatility3 venv's own Python interpreter (a
 * sibling of the resolved `vol` binary — no separate settings field
 * needed). Mirrors volatility.ts's spawn/JSON-result conventions but the
 * "renderer" here is a small hand-rolled JSON-lines protocol over stdout,
 * since Yara has no equivalent of Volatility3's `-r jsonl`.
 */
import { spawn } from "child_process";
import path from "path";

export interface YaraRuleSpec {
  id: string;
  yaraSource: string;
}

export interface YaraMatch {
  ruleId: string;
  ruleName: string;
  identifier: string;
  offset: number;
  matchedDataHex: string;
}

export interface YaraCompileError {
  ruleId: string;
  message: string;
}

export type YaraScanResult =
  | { status: "ok"; matches: YaraMatch[]; compileErrors: YaraCompileError[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_YARA_TIMEOUT_SECONDS = 20 * 60; // mirrors volatility.ts's own 20-minute default

/**
 * Compiles a single Yara source string without scanning anything — used
 * by the create/update rule API routes to reject invalid Yara syntax at
 * save time with a real error message, rather than silently dropping the
 * bad rule later during a scan (yara-scan.py still guards against this
 * independently, since a rule edited directly in the DB could bypass the
 * API, but this is what gives the analyst immediate feedback in the UI).
 */
export async function validateYaraSource(
  volPath: string,
  source: string
): Promise<{ valid: true } | { valid: false; message: string }> {
  const pythonPath = path.join(path.dirname(volPath), "python3");
  const code = "import sys\ntry:\n    import yara\nexcept ImportError:\n    sys.exit(0)\ntry:\n    yara.compile(source=sys.stdin.read())\nexcept Exception as e:\n    print(str(e))\n    sys.exit(1)\n";

  return new Promise((resolve) => {
    const child = spawn(pythonPath, ["-c", code], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.on("error", () => resolve({ valid: true })); // interpreter missing entirely — treat as unvalidatable, not invalid
    child.on("close", (exitCode) => {
      if (exitCode !== 0) resolve({ valid: false, message: stdout.trim() || "Invalid Yara syntax" });
      else resolve({ valid: true });
    });
    child.stdin.write(source);
    child.stdin.end();
  });
}

export async function runYaraScan(
  volPath: string,
  imagePath: string,
  rules: YaraRuleSpec[],
  timeoutSeconds: number = DEFAULT_YARA_TIMEOUT_SECONDS
): Promise<YaraScanResult> {
  if (rules.length === 0) return { status: "ok", matches: [], compileErrors: [] };

  const pythonPath = path.join(path.dirname(volPath), "python3");
  const scriptPath = path.join(process.cwd(), "src", "lib", "ram-analysis", "yara-scan.py");

  return new Promise<YaraScanResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, imagePath, String(timeoutSeconds)], { stdio: ["pipe", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    // Node-level backstop in case the process stalls before yara's own
    // internal timeout can fire (e.g. hung on I/O) — a bit longer than
    // the timeout passed to the script itself.
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 30) * 1000);

    const settle = (result: YaraScanResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdin.write(JSON.stringify(rules));
    child.stdin.end();

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run yara-scan.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      const matches: YaraMatch[] = [];
      const compileErrors: YaraCompileError[] = [];
      let notInstalled = false;
      let errorMessage: string | null = null;

      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let obj: Record<string, unknown>;
        try { obj = JSON.parse(trimmed); } catch { continue; }
        switch (obj.type) {
          case "not_installed":
            notInstalled = true;
            break;
          case "compile_error":
            compileErrors.push({ ruleId: String(obj.ruleId), message: String(obj.message) });
            break;
          case "match":
            matches.push({
              ruleId: String(obj.ruleId),
              ruleName: String(obj.ruleName),
              identifier: String(obj.identifier),
              offset: Number(obj.offset),
              matchedDataHex: String(obj.matchedDataHex),
            });
            break;
          case "error":
            errorMessage = String(obj.message);
            break;
        }
      }

      if (notInstalled) { settle({ status: "not_installed" }); return; }
      if (errorMessage) { settle({ status: "error", message: errorMessage }); return; }
      if (exitCode !== 0) {
        const detail = (stderr || stdout).trim().slice(0, 500);
        settle({ status: "error", message: detail || `yara-scan.py exited with code ${exitCode}` });
        return;
      }
      settle({ status: "ok", matches, compileErrors });
    });
  });
}
