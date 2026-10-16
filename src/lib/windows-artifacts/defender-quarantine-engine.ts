/**
 * Spawns the Windows Artifacts venv's python3 running
 * defender-quarantine-parse.py — two entry points in one script:
 * `entries` mode RC4-decrypts a Quarantine\Entries metadata file and
 * reads its TLV structure (Fox-IT's published, partial field-ID map);
 * `resource` mode RC4-decrypts a Quarantine\ResourceData payload file and
 * writes the decrypted bytes to disk (storagePath passed in). Same
 * spawn/collect/timeout/discriminated-result convention as
 * jumplist-engine.ts, parameterized by mode since the two file kinds need
 * different script arguments.
 */
import { spawn } from "child_process";
import path from "path";

export interface QuarantineResourceField {
  detectionPath: string | null;
  detectionType: string | null;
  creationTime: string | null;
  lastAccessTime: string | null;
  lastWriteTime: string | null;
  physicalPath: string | null;
  flags: number | null;
  unknownFields: { id: number; type: number; value: string }[];
}

export interface QuarantineEntryRow {
  entryIdHex: string | null;
  scanIdHex: string | null;
  threatId: string | null;
  detectionName: string | null;
  timestamp: string | null;
  resources: QuarantineResourceField[];
  rawFields: Record<string, unknown>;
}

export type QuarantineEntryParseResult =
  | { status: "ok"; entry: QuarantineEntryRow | null; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

export interface QuarantinePayloadRow {
  magicValid: boolean;
  sha256: string | null;
  decryptedSizeBytes: string | null;
  fileTypeSniff: string | null;
}

export type QuarantinePayloadParseResult =
  | { status: "ok"; entry: QuarantinePayloadRow | null; scriptErrors: string[] }
  | { status: "not_installed" }
  | { status: "timeout" }
  | { status: "error"; message: string };

const DEFAULT_TIMEOUT_SECONDS = 2 * 60;

function spawnAndCollect(pythonPath: string, args: string[], timeoutSeconds: number): Promise<{ lines: Record<string, unknown>[]; stderr: string; exitCode: number | null; timedOut: boolean }> {
  return new Promise((resolve) => {
    const child = spawn(pythonPath, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, (timeoutSeconds + 10) * 1000);

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ lines: [], stderr: err.message, exitCode: null, timedOut: false });
    });

    child.on("close", (exitCode) => {
      clearTimeout(timer);
      const lines: Record<string, unknown>[] = [];
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try { lines.push(JSON.parse(trimmed)); } catch { continue; }
      }
      resolve({ lines, stderr, exitCode, timedOut });
    });
  });
}

export async function runQuarantineEntryParse(
  pythonPath: string,
  entriesFilePath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<QuarantineEntryParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "defender-quarantine-parse.py");
  const { lines, stderr, exitCode, timedOut } = await spawnAndCollect(pythonPath, [scriptPath, "entries", entriesFilePath], timeoutSeconds);

  if (timedOut) return { status: "timeout" };
  if (exitCode === null) return { status: "error", message: `Failed to run defender-quarantine-parse.py ("${pythonPath}"): ${stderr}` };

  const scriptErrors: string[] = [];
  let entry: QuarantineEntryRow | null = null;
  let notInstalled = false;

  for (const obj of lines) {
    switch (obj.type) {
      case "not_installed":
        notInstalled = true;
        break;
      case "quarantine_entry":
        entry = {
          entryIdHex: obj.entry_id_hex != null ? String(obj.entry_id_hex) : null,
          scanIdHex: obj.scan_id_hex != null ? String(obj.scan_id_hex) : null,
          threatId: obj.threat_id != null ? String(obj.threat_id) : null,
          detectionName: obj.detection_name != null ? String(obj.detection_name) : null,
          timestamp: obj.timestamp != null ? String(obj.timestamp) : null,
          resources: Array.isArray(obj.resources)
            ? obj.resources.map((r) => {
                const row = r as Record<string, unknown>;
                return {
                  detectionPath: row.detection_path != null ? String(row.detection_path) : null,
                  detectionType: row.detection_type != null ? String(row.detection_type) : null,
                  creationTime: row.creation_time != null ? String(row.creation_time) : null,
                  lastAccessTime: row.last_access_time != null ? String(row.last_access_time) : null,
                  lastWriteTime: row.last_write_time != null ? String(row.last_write_time) : null,
                  physicalPath: row.physical_path != null ? String(row.physical_path) : null,
                  flags: row.flags != null ? Number(row.flags) : null,
                  unknownFields: Array.isArray(row.unknown_fields)
                    ? row.unknown_fields.map((u) => {
                        const uf = u as Record<string, unknown>;
                        return { id: Number(uf.id ?? 0), type: Number(uf.type ?? 0), value: String(uf.value ?? "") };
                      })
                    : [],
                };
              })
            : [],
          rawFields: typeof obj.raw_fields === "object" && obj.raw_fields !== null ? (obj.raw_fields as Record<string, unknown>) : {},
        };
        break;
      case "error":
        scriptErrors.push(String(obj.message));
        break;
    }
  }

  if (notInstalled) return { status: "not_installed" };
  if (exitCode !== 0 && !entry) {
    const detail = (stderr || scriptErrors.join("; ")).trim().slice(0, 500);
    return { status: "error", message: detail || `defender-quarantine-parse.py exited with code ${exitCode}` };
  }

  return { status: "ok", entry, scriptErrors };
}

export async function runQuarantinePayloadParse(
  pythonPath: string,
  resourceFilePath: string,
  decryptedOutputPath: string,
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS
): Promise<QuarantinePayloadParseResult> {
  const scriptPath = path.join(process.cwd(), "src", "lib", "windows-artifacts", "defender-quarantine-parse.py");
  const { lines, stderr, exitCode, timedOut } = await spawnAndCollect(pythonPath, [scriptPath, "resource", resourceFilePath, decryptedOutputPath], timeoutSeconds);

  if (timedOut) return { status: "timeout" };
  if (exitCode === null) return { status: "error", message: `Failed to run defender-quarantine-parse.py ("${pythonPath}"): ${stderr}` };

  const scriptErrors: string[] = [];
  let entry: QuarantinePayloadRow | null = null;
  let notInstalled = false;

  for (const obj of lines) {
    switch (obj.type) {
      case "not_installed":
        notInstalled = true;
        break;
      case "quarantine_payload":
        entry = {
          magicValid: Boolean(obj.magic_valid),
          sha256: obj.sha256 != null ? String(obj.sha256) : null,
          decryptedSizeBytes: obj.decrypted_size_bytes != null ? String(obj.decrypted_size_bytes) : null,
          fileTypeSniff: obj.file_type_sniff != null ? String(obj.file_type_sniff) : null,
        };
        break;
      case "error":
        scriptErrors.push(String(obj.message));
        break;
    }
  }

  if (notInstalled) return { status: "not_installed" };
  if (exitCode !== 0 && !entry) {
    const detail = (stderr || scriptErrors.join("; ")).trim().slice(0, 500);
    return { status: "error", message: detail || `defender-quarantine-parse.py exited with code ${exitCode}` };
  }

  return { status: "ok", entry, scriptErrors };
}
