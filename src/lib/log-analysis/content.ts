/**
 * Turning an uploaded log file's bytes into the line-oriented text the
 * decoder engine expects — three cases the plain `buffer.toString("utf-8")`
 * upload path got wrong:
 *
 *  - Raw Windows .evtx (binary "ElfFile" format) — converted to single-line
 *    Event XML via evtx-to-xml.py (python-evtx), the same shape the
 *    collector's LogChannels\*.log export and the Windows decoders use.
 *  - UTF-16 text (Defender/many Windows tools, PowerShell's default
 *    Out-File encoding) — decoded instead of producing NUL-interleaved junk.
 *  - Event XML whose event data contains newlines (PowerShell 4104 script
 *    blocks, multi-line messages): .ToXml() keeps them literally, so one
 *    event spans several lines and the line splitter would cut it into
 *    fragments no decoder matches. Continuation lines are re-joined.
 */
import { spawn } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { gunzipSync } from "zlib";

export function isEvtx(buffer: Buffer, filename: string): boolean {
  return filename.toLowerCase().endsWith(".evtx") || buffer.subarray(0, 8).toString("latin1") === "ElfFile\0";
}

export function decodeLogBuffer(buffer: Buffer): string {
  // .gz uploads (offered by the upload page) were previously read as raw
  // compressed bytes — decompress first, then detect the text encoding.
  if (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) {
    return decodeLogBuffer(gunzipSync(buffer));
  }
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.subarray(2).toString("utf16le");
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
    const swapped = Buffer.from(buffer.subarray(2));
    swapped.swap16();
    return swapped.toString("utf16le");
  }
  // BOM-less UTF-16LE: printable ASCII interleaved with NULs.
  if (buffer.length >= 4 && buffer[1] === 0 && buffer[3] === 0 && buffer[0] !== 0 && buffer[2] !== 0) {
    return buffer.toString("utf16le");
  }
  const text = buffer.toString("utf-8");
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/** Re-joins Event XML records that were split across lines by literal
 * newlines in their data, escaping the joined newline as &#10;. Lines that
 * aren't part of an unterminated <Event> pass through untouched. */
export function joinMultilineEventXml(text: string): string {
  if (!text.includes("<Event xmlns")) return text;
  const out: string[] = [];
  let pending: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (pending !== null) {
      pending += "&#10;" + line;
      if (line.includes("</Event>")) { out.push(pending); pending = null; }
      continue;
    }
    if (line.trimStart().startsWith("<Event xmlns") && !line.includes("</Event>")) {
      pending = line;
      continue;
    }
    out.push(line);
  }
  if (pending !== null) out.push(pending);
  return out.join("\n");
}

export type EvtxConversion =
  | { status: "ok"; text: string; events: number; failed: number; truncated: boolean }
  | { status: "not_installed" }
  | { status: "error"; message: string };

export async function convertEvtx(pythonPath: string, buffer: Buffer, maxEvents = 200000, timeoutSeconds = 20 * 60): Promise<EvtxConversion> {
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "fz-evtx-"));
  const tmpFile = path.join(tmpDir, "upload.evtx");
  await fs.promises.writeFile(tmpFile, buffer);
  const scriptPath = path.join(process.cwd(), "src", "lib", "log-analysis", "evtx-to-xml.py");

  try {
    return await new Promise<EvtxConversion>((resolve) => {
      const child = spawn(pythonPath, [scriptPath, tmpFile, String(maxEvents)], { stdio: ["ignore", "pipe", "pipe"] });
      const chunks: Buffer[] = [];
      let stderr = "";
      const timer = setTimeout(() => child.kill("SIGKILL"), timeoutSeconds * 1000);
      child.stdout.on("data", (c: Buffer) => chunks.push(c));
      child.stderr.on("data", (c) => { if (stderr.length < 5000) stderr += c.toString(); });
      child.on("error", (err) => { clearTimeout(timer); resolve({ status: "error", message: err.message }); });
      child.on("close", (code) => {
        clearTimeout(timer);
        const out = Buffer.concat(chunks).toString("utf-8");
        const marker = out.lastIndexOf("#FZ-EVTX-SUMMARY ");
        if (marker < 0) {
          resolve({ status: "error", message: (stderr || `evtx-to-xml.py exited with code ${code}`).slice(0, 500) });
          return;
        }
        let summary: { events?: number; failed?: number; truncated?: boolean; error?: string } = {};
        try { summary = JSON.parse(out.slice(marker + "#FZ-EVTX-SUMMARY ".length).trim()); } catch { /* keep empty */ }
        if (summary.error === "not_installed") { resolve({ status: "not_installed" }); return; }
        resolve({ status: "ok", text: out.slice(0, marker), events: summary.events ?? 0, failed: summary.failed ?? 0, truncated: !!summary.truncated });
      });
    });
  } finally {
    await fs.promises.rm(tmpDir, { recursive: true, force: true });
  }
}
