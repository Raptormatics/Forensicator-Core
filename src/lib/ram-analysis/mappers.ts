/**
 * Converts raw Volatility3 JSON-line rows into typed shapes. Column names
 * below are taken directly from the installed volatility3 2.28.0 framework's
 * plugin source (each plugin's `TreeGrid(...)` column list) rather than
 * guessed — see windows/pslist.py, windows/netscan.py,
 * windows/malware/malfind.py, windows/cmdline.py, windows/info.py,
 * linux/pslist.py, linux/psaux.py, linux/sockstat.py,
 * linux/malware/malfind.py, mac/pslist.py, mac/psaux.py, mac/netstat.py,
 * mac/malfind.py, and the top-level banners.py.
 */
import type { VolatilityRow } from "./volatility";
import type { RamProcessRow, RamConnectionRow, RamMalfindHit, RamInfoSummary } from "./types";

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** Some plugins declare a numeric-looking column as `str` in their
 * TreeGrid (e.g. linux.sockstat's Source/Destination Port) — JSON then
 * carries it as a string, not a number. */
function numFromStr(v: unknown): number | null {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v !== "string" || !v) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function date(v: unknown): Date | null {
  if (typeof v !== "string" || !v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * format_hints.Hex columns (e.g. malfind's Start VPN/End VPN) have no
 * special-case entry in Volatility3's JsonLinesRenderer._type_renderers
 * (confirmed against the installed framework's text_renderer.py) — they
 * fall through to the "default" identity renderer, so json.dumps emits
 * them as a plain integer, not a "0x..." string. Format it ourselves.
 */
function hexAddr(v: unknown): string | null {
  const n = num(v);
  return n === null ? null : `0x${n.toString(16)}`;
}

export function mapPsListRows(rows: VolatilityRow[]): RamProcessRow[] {
  return rows.map((r) => ({
    pid:         num(r["PID"]) ?? 0,
    ppid:        num(r["PPID"]),
    name:        str(r["ImageFileName"]) ?? "(unknown)",
    threads:     num(r["Threads"]),
    handles:     num(r["Handles"]),
    sessionId:   num(r["SessionId"]),
    owner:       null,
    createTime:  date(r["CreateTime"]),
    exitTime:    date(r["ExitTime"]),
    commandLine: null,
    path:        null,
  }));
}

/** First token of a command line as a best-effort executable path — pslist
 * has no dedicated path column, and this can't distinguish a quoted path
 * with spaces from a bare unquoted one. Documented approximation, not a
 * bug: null just means cmdline enrichment didn't cover this pid. */
function guessPathFromCmdLine(args: string): string | null {
  const trimmed = args.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('"')) {
    const end = trimmed.indexOf('"', 1);
    return end > 0 ? trimmed.slice(1, end) : null;
  }
  return trimmed.split(/\s+/)[0] || null;
}

/** Merges windows.cmdline.CmdLine rows into an existing RamProcessRow[] by pid. */
export function mergeCmdLine(processes: RamProcessRow[], cmdlineRows: VolatilityRow[]): RamProcessRow[] {
  const byPid = new Map<number, string>();
  for (const r of cmdlineRows) {
    const pid = num(r["PID"]);
    const args = str(r["Args"]);
    if (pid !== null && args !== null) byPid.set(pid, args);
  }
  return processes.map((p) => {
    const args = byPid.get(p.pid);
    if (!args) return p;
    return { ...p, commandLine: args, path: guessPathFromCmdLine(args) };
  });
}

export function mapNetScanRows(rows: VolatilityRow[]): RamConnectionRow[] {
  return rows.map((r) => ({
    protocol:    str(r["Proto"]),
    localAddr:   str(r["LocalAddr"]),
    localPort:   num(r["LocalPort"]),
    foreignAddr: str(r["ForeignAddr"]),
    foreignPort: num(r["ForeignPort"]),
    state:       str(r["State"]),
    pid:         num(r["PID"]),
    processName: str(r["Owner"]),
    created:     date(r["Created"]),
  }));
}

export function mapMalfindRows(rows: VolatilityRow[]): RamMalfindHit[] {
  return rows.map((r) => ({
    pid:           num(r["PID"]),
    process:       str(r["Process"]),
    tag:           str(r["Tag"]),
    protection:    str(r["Protection"]),
    commitCharge:  num(r["CommitCharge"]),
    privateMemory: num(r["PrivateMemory"]),
    path:          null,
    startAddress:  hexAddr(r["Start VPN"]),
    endAddress:    hexAddr(r["End VPN"]),
    previewHex:    str(r["Hexdump"]),
  }));
}

// ── Linux ────────────────────────────────────────────────────────────────

export function mapLinuxPsListRows(rows: VolatilityRow[]): RamProcessRow[] {
  return rows.map((r) => ({
    pid:         num(r["PID"]) ?? 0,
    ppid:        num(r["PPID"]),
    name:        str(r["COMM"]) ?? "(unknown)",
    threads:     null,
    handles:     null,
    sessionId:   null,
    owner:       num(r["UID"]) !== null ? String(num(r["UID"])) : null,
    createTime:  date(r["CREATION TIME"]),
    exitTime:    null,
    commandLine: null,
    path:        null,
  }));
}

/** Merges linux.psaux.PsAux rows into an existing RamProcessRow[] by pid. */
export function mergeLinuxPsaux(processes: RamProcessRow[], psauxRows: VolatilityRow[]): RamProcessRow[] {
  const byPid = new Map<number, string>();
  for (const r of psauxRows) {
    const pid = num(r["PID"]);
    const args = str(r["ARGS"]);
    if (pid !== null && args !== null) byPid.set(pid, args);
  }
  return processes.map((p) => {
    const args = byPid.get(p.pid);
    if (!args) return p;
    return { ...p, commandLine: args, path: guessPathFromCmdLine(args) };
  });
}

export function mapLinuxSockstatRows(rows: VolatilityRow[]): RamConnectionRow[] {
  return rows.map((r) => ({
    protocol:    str(r["Proto"]),
    localAddr:   str(r["Source Addr"]),
    localPort:   numFromStr(r["Source Port"]),
    foreignAddr: str(r["Destination Addr"]),
    foreignPort: numFromStr(r["Destination Port"]),
    state:       str(r["State"]),
    pid:         num(r["PID"]),
    processName: str(r["Process Name"]),
    created:     null,
  }));
}

export function mapLinuxMalfindRows(rows: VolatilityRow[]): RamMalfindHit[] {
  return rows.map((r) => ({
    pid:           num(r["PID"]),
    process:       str(r["Process"]),
    tag:           null,
    protection:    str(r["Protection"]),
    commitCharge:  null,
    privateMemory: null,
    path:          str(r["Path"]),
    startAddress:  hexAddr(r["Start"]),
    endAddress:    hexAddr(r["End"]),
    previewHex:    str(r["Hexdump"]),
  }));
}

// ── macOS ────────────────────────────────────────────────────────────────

export function mapMacPsListRows(rows: VolatilityRow[]): RamProcessRow[] {
  return rows.map((r) => ({
    pid:         num(r["PID"]) ?? 0,
    ppid:        num(r["PPID"]),
    name:        str(r["NAME"]) ?? "(unknown)",
    threads:     null,
    handles:     null,
    sessionId:   null,
    owner:       num(r["UID"]) !== null ? String(num(r["UID"])) : null,
    createTime:  date(r["Start Time"]),
    exitTime:    null,
    commandLine: null,
    path:        null,
  }));
}

/** Merges mac.psaux.PsAux rows into an existing RamProcessRow[] by pid. */
export function mergeMacPsaux(processes: RamProcessRow[], psauxRows: VolatilityRow[]): RamProcessRow[] {
  const byPid = new Map<number, string>();
  for (const r of psauxRows) {
    const pid = num(r["PID"]);
    const args = str(r["Arguments"]);
    if (pid !== null && args !== null) byPid.set(pid, args);
  }
  return processes.map((p) => {
    const args = byPid.get(p.pid);
    if (!args) return p;
    return { ...p, commandLine: args, path: guessPathFromCmdLine(args) };
  });
}

export function mapMacNetstatRows(rows: VolatilityRow[]): RamConnectionRow[] {
  return rows.map((r) => ({
    protocol:    str(r["Proto"]),
    localAddr:   str(r["Local IP"]),
    localPort:   num(r["Local Port"]),
    foreignAddr: str(r["Remote IP"]),
    foreignPort: num(r["Remote Port"]),
    state:       str(r["State"]),
    pid:         null, // mac.netstat.Netstat has no PID column, only a process name
    processName: str(r["Process"]),
    created:     null,
  }));
}

export function mapMacMalfindRows(rows: VolatilityRow[]): RamMalfindHit[] {
  return rows.map((r) => ({
    pid:           num(r["PID"]),
    process:       str(r["Process"]),
    tag:           null,
    protection:    str(r["Protection"]),
    commitCharge:  null,
    privateMemory: null,
    path:          null,
    startAddress:  hexAddr(r["Start"]),
    endAddress:    hexAddr(r["End"]),
    previewHex:    str(r["Hexdump"]),
  }));
}

// ── Cross-platform (Linux/macOS) ────────────────────────────────────────

/** banners.Banners yields flat Offset/Banner rows scanning the raw image
 * for "Linux version ..."/"Darwin Kernel Version ..." strings — no symbol
 * table required, so it still works even when nothing else does. Used as
 * the Linux/macOS "OS detection" step and, on a subsequent pslist
 * failure, to tell the user exactly what banner their custom symbol table
 * needs to match. osArch is left null — not derivable from the banner
 * text alone. */
export function mapBannerRows(rows: VolatilityRow[]): RamInfoSummary {
  for (const r of rows) {
    const banner = str(r["Banner"]);
    if (banner && (banner.startsWith("Linux version") || banner.startsWith("Darwin Kernel Version"))) {
      return { osBuild: banner, osArch: null };
    }
  }
  return { osBuild: null, osArch: null };
}

/** Maps a numeric/textual PE machine-type value to a display architecture.
 * IMAGE_FILE_MACHINE_AMD64=0x8664 (34404), IMAGE_FILE_MACHINE_I386=0x14c (332) —
 * the only two constants v1 needs to distinguish; anything else is "unknown"
 * rather than guessed. */
function archFromMachineType(value: string | null): string | null {
  if (!value) return null;
  const v = value.toLowerCase();
  if (v.includes("34404") || v.includes("8664") || v.includes("amd64") || v.includes("x64")) return "x64";
  if (v.includes("332") || v.includes("14c") || v.includes("i386") || v.includes("x86")) return "x86";
  return "unknown";
}

/** windows.info.Info yields flat Variable/Value rows (not a fixed schema) —
 * pick out just the fields RamUpload.osBuild/osArch need. */
export function mapInfoRows(rows: VolatilityRow[]): RamInfoSummary {
  const kv = new Map<string, string>();
  for (const r of rows) {
    const variable = str(r["Variable"]);
    const value = str(r["Value"]);
    if (variable) kv.set(variable, value ?? "");
  }
  const ntBuildLab = kv.get("NTBuildLab");
  const majorMinor = kv.get("Major/Minor");
  const osBuild = ntBuildLab || majorMinor || null;
  const osArch = archFromMachineType(kv.get("PE Machine") ?? kv.get("MachineType") ?? null);
  return { osBuild, osArch };
}
