/**
 * Runs a single Volatility3 plugin against a memory image and returns its
 * rows. One process per plugin — `vol` has no equivalent to tshark's
 * streaming `-T fields`, each plugin invocation produces its own complete
 * result set.
 *
 * Renderer is `-r jsonl` (JSON Lines), not `-r json` — confirmed against
 * the installed framework's renderer source (volatility3/cli/text_renderer.py):
 * `-r json` pretty-prints one big indented array (the whole result buffered
 * as a single JSON.parse target), while `-r jsonl` writes one compact JSON
 * object per line, which is both cheaper to parse here and consistent with
 * this codebase's other line-oriented external-tool parsing (see
 * pcap-analysis/tshark.ts). Both renderers write a stray leading blank line
 * before any output — filtered out below, not a parsing bug.
 *
 * Volatility3 has no `--version` flag and prints its usage banner (not a
 * version string) on `-h`; error text is not written to stderr like most
 * CLIs — confirmed against a real install, "Unsatisfied requirement..."
 * messages print to stdout, with a non-zero exit code as the real success
 * signal. Never trust stdout content alone to detect failure.
 */
import { spawn } from "child_process";

export type VolatilityRow = Record<string, unknown>;

export type VolatilityPluginResult =
  | { status: "ok"; rows: VolatilityRow[] }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_PLUGIN_TIMEOUT_MS = 20 * 60 * 1000; // 20 minutes — env-tunable, see runVolatilityPlugin

export interface RunPluginOptions {
  symbolsDir?: string | null;
  timeoutMs?: number;
  /** `-o <dir>` — where plugin-triggered file output (e.g. malfind --dump) is written. */
  outputDir?: string;
  /** Extra plugin-specific flags, appended after the plugin name (e.g. ["--pid", "1234", "--dump"]). */
  pluginArgs?: string[];
}

function parseJsonLines(stdout: string): VolatilityRow[] {
  const rows: VolatilityRow[] = [];
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      rows.push(JSON.parse(trimmed) as VolatilityRow);
    } catch {
      // A non-JSON stray line (banner/log noise slipping onto stdout) —
      // skip it rather than failing the whole plugin over one bad line.
    }
  }
  return rows;
}

/**
 * Runs `<volPath> -q -f <dumpPath> [-s <symbolsDir>] -r jsonl <pluginName>`.
 * Never throws — timeouts and non-zero exits are reported via the returned
 * discriminated result so the caller (processor.ts) can decide per-plugin
 * whether a failure is fatal or degradable.
 */
export async function runVolatilityPlugin(
  volPath: string,
  dumpPath: string,
  pluginName: string,
  opts: RunPluginOptions = {}
): Promise<VolatilityPluginResult> {
  const envTimeout = Number(process.env.VOLATILITY_PLUGIN_TIMEOUT_MS);
  const timeoutMs = opts.timeoutMs ?? (envTimeout > 0 ? envTimeout : DEFAULT_PLUGIN_TIMEOUT_MS);

  const args = ["-q", "-f", dumpPath];
  if (opts.symbolsDir) args.push("-s", opts.symbolsDir);
  if (opts.outputDir) args.push("-o", opts.outputDir);
  args.push("-r", "jsonl", pluginName);
  if (opts.pluginArgs) args.push(...opts.pluginArgs);

  return new Promise<VolatilityPluginResult>((resolve) => {
    const child = spawn(volPath, args, { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    const settle = (result: VolatilityPluginResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run vol ("${volPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }
      if (exitCode !== 0) {
        const detail = (stdout || stderr).trim().slice(0, 500);
        settle({ status: "error", message: `${pluginName} exited with code ${exitCode}${detail ? `: ${detail}` : ""}` });
        return;
      }
      settle({ status: "ok", rows: parseJsonLines(stdout) });
    });
  });
}
