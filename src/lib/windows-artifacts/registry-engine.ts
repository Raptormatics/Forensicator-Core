/**
 * Spawns the Windows Artifact Analysis venv's python3 running
 * registry-parse.py against a single registry hive, parsing its
 * JSON-lines stdout protocol — same spawn/collect/timeout/discriminated-
 * result convention as src/lib/yara/engine.ts and
 * src/lib/ram-analysis/volatility.ts.
 */
import { spawn } from "child_process";
import path from "path";

export type RegistryRole = "system_hive" | "software_hive" | "ntuser_hive" | "amcache_hive";

export interface RegistryPluginEntry {
  plugin: string;
  data: Record<string, unknown>;
}

export interface AutorunRow {
  hiveSource: string;
  keyPath: string;
  valueName: string | null;
  valueData: string;
  category: string;
}

export interface UserAssistRow {
  programPath: string;
  runCount: number | null;
  lastExecuted: string | null;
  focusCount: number | null;
  focusTimeMs: number | null;
}

export type RegistryParseResult =
  | { status: "ok"; pluginEntries: RegistryPluginEntry[]; autoruns: AutorunRow[]; userAssist: UserAssistRow[]; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 5 * 60; // registry hives are small; generous but not RAM-plugin-scale

export async function runRegistryParse(
  pythonPath: string,
  hivePath: string,
  role: RegistryRole,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<RegistryParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "registry-parse.py");

  return new Promise<RegistryParseResult>((resolve) => {
    const child = spawn(pythonPath, [scriptPath, hivePath, role], { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    const settle = (result: RegistryParseResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      settle({ status: "error", message: `Failed to run registry-parse.py ("${pythonPath}"): ${err.message}` });
    });

    child.on("close", (exitCode) => {
      if (timedOut) {
        settle({ status: "timeout" });
        return;
      }

      const pluginEntries: RegistryPluginEntry[] = [];
      const autoruns: AutorunRow[] = [];
      const userAssist: UserAssistRow[] = [];
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
          case "plugin_entry":
            pluginEntries.push({ plugin: String(obj.plugin), data: (obj.data as Record<string, unknown>) ?? {} });
            break;
          case "autorun":
            autoruns.push({
              hiveSource: String(obj.hive_source ?? ""),
              keyPath: String(obj.key_path ?? ""),
              valueName: obj.value_name != null ? String(obj.value_name) : null,
              valueData: String(obj.value_data ?? ""),
              category: String(obj.category ?? ""),
            });
            break;
          case "userassist":
            userAssist.push({
              programPath: String(obj.program_path ?? ""),
              runCount: obj.run_count != null ? Number(obj.run_count) : null,
              lastExecuted: obj.last_executed ? String(obj.last_executed) : null,
              focusCount: obj.focus_count != null ? Number(obj.focus_count) : null,
              focusTimeMs: obj.focus_time_ms != null ? Number(obj.focus_time_ms) : null,
            });
            break;
          case "error":
            scriptErrors.push(String(obj.message));
            break;
        }
      }

      if (notInstalled) { settle({ status: "not_installed" }); return; }

      const gotAnything = pluginEntries.length > 0 || autoruns.length > 0 || userAssist.length > 0;
      if (exitCode !== 0 && !gotAnything) {
        const detail = (stderr || scriptErrors.join("; ") || stdout).trim().slice(0, 500);
        settle({ status: "error", message: detail || `registry-parse.py exited with code ${exitCode}` });
        return;
      }

      settle({ status: "ok", pluginEntries, autoruns, userAssist, scriptErrors });
    });
  });
}

// ── Lenient plugin-entry → typed row mapping ────────────────────────────────
// regipy's exact per-plugin output field names couldn't be verified against
// a live install while building this feature (see registry-parse.py's own
// header comment) — these mappers try several plausible candidate keys per
// field rather than assuming one exact name, so a reasonable field-name
// guess still produces a usable row instead of silently dropping data.
// If rows come through with unexpectedly-null fields once this runs against
// a real regipy install, inspect RegistryPluginEntry.data directly (it's
// the plugin's raw, unmodified output) and add the real key name here.

function pick(data: Record<string, unknown>, keys: string[]): unknown {
  for (const k of keys) {
    if (data[k] !== undefined && data[k] !== null) return data[k];
  }
  return undefined;
}

function str(v: unknown): string | null {
  return v == null ? null : String(v);
}

function num(v: unknown): number | null {
  if (v == null) return null;
  const n = Number(v);
  return Number.isNaN(n) ? null : n;
}

export interface ShimcacheRow { path: string; lastModified: string | null; executionFlag: boolean | null; order: number }
export interface AmcacheRow { path: string; sha1: string | null; fileSizeBytes: bigint | null; firstSeen: string | null; publisher: string | null }
export interface BamRow { sid: string; path: string; lastExecuted: string | null }

export function mapShimcacheEntries(entries: RegistryPluginEntry[]): ShimcacheRow[] {
  return entries
    .filter((e) => e.plugin.toLowerCase().includes("shimcache") || e.plugin.toLowerCase().includes("appcompatcache"))
    .map((e, i) => {
      const path = str(pick(e.data, ["path", "entry", "name", "cached_file_path"]));
      if (!path) return null;
      // regipy's ShimCacheParser yields exec_flag as the literal string
      // "True"/"False" (not a JSON boolean) on OS versions where it's
      // present at all — confirmed by reading the vendored
      // ShimCacheParser.py source directly. `Boolean("False")` would be
      // `true`, so this needs an explicit string comparison, not a cast.
      const execRaw = pick(e.data, ["executed", "execution_flag", "exec_flag"]);
      let executionFlag: boolean | null;
      if (typeof execRaw === "boolean") executionFlag = execRaw;
      else if (typeof execRaw === "string") executionFlag = execRaw.toLowerCase() === "true";
      else executionFlag = null;
      return {
        path,
        lastModified: str(pick(e.data, ["last_modified", "last_mod_date", "last_mod_time", "modification_time"])),
        executionFlag,
        order: num(pick(e.data, ["index", "order", "entry_order"])) ?? i,
      };
    })
    .filter((r): r is ShimcacheRow => r !== null);
}

export function mapAmcacheEntries(entries: RegistryPluginEntry[]): AmcacheRow[] {
  return entries
    .filter((e) => e.plugin.toLowerCase().includes("amcache"))
    .map((e) => {
      const path = str(pick(e.data, ["path", "full_path", "file_path", "name"]));
      if (!path) return null;
      let sha1 = str(pick(e.data, ["sha1", "file_id", "sha1_hash"]));
      // Amcache's own InventoryApplicationFile rows carry a well-known
      // leading "0000" prefix on the SHA1 (a storage quirk, not part of
      // the real hash) — strip it if present.
      if (sha1 && /^0000[0-9a-f]{40}$/i.test(sha1)) sha1 = sha1.slice(4);
      const sizeRaw = pick(e.data, ["file_size", "size", "file_size_bytes"]);
      return {
        path,
        sha1,
        fileSizeBytes: sizeRaw != null && !Number.isNaN(Number(sizeRaw)) ? BigInt(Math.trunc(Number(sizeRaw))) : null,
        firstSeen: str(pick(e.data, ["first_seen", "created_timestamp", "timestamp", "key_last_write", "install_date", "link_date"])),
        publisher: str(pick(e.data, ["publisher", "product_name"])),
      };
    })
    .filter((r): r is AmcacheRow => r !== null);
}

export function mapBamEntries(entries: RegistryPluginEntry[]): BamRow[] {
  return entries
    // regipy's actual plugin name is "background_activity_moderator" — no
    // "bam" substring — confirmed by reading bam.py's NAME constant
    // directly. Matched on "activity_moderator" plus the historical "bam"/
    // "dam" aliases in case of a future regipy rename.
    .filter((e) => {
      const p = e.plugin.toLowerCase();
      return p.includes("activity_moderator") || p.includes("bam") || p.includes("dam");
    })
    .map((e) => {
      const path = str(pick(e.data, ["executable", "path", "application", "name"]));
      if (!path) return null;
      return {
        sid: str(pick(e.data, ["sid", "user_sid"])) ?? "unknown",
        path,
        lastExecuted: str(pick(e.data, ["last_executed", "timestamp", "execution_time"])),
      };
    })
    .filter((r): r is BamRow => r !== null);
}
