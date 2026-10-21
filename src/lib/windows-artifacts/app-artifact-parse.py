#!/usr/bin/env python3
"""
Application artifacts collected by the Live Forensicator collector under
WindowsArtifacts\\ApplicationArtifacts\\<target>\\<profile|System>\\...:
cloud-sync client metadata/logs (OneDrive, Dropbox, Google Drive), endpoint
security product logs (CrowdStrike, SentinelOne, Sophos, ESET, Malwarebytes,
Bitdefender, McAfee, Trend Micro), remote-access tool logs (AnyDesk,
TeamViewer, ScreenConnect, RustDesk, Splashtop, LogMeIn), Windows Notepad /
Notepad++ unsaved state, and analyst-configured custom targets.

Invoked as: app-artifact-parse.py <file> <target folder name> <relative path>

Dispatch is by target name and file name; anything without a dedicated
parser falls through to a generic text/SQLite/JSON/INI handler that keeps
only lines carrying an indicator (URL/IP/e-mail/path/hash) or an
access-related keyword, so a chatty EDR debug log doesn't become 100k rows.

Dedicated parsers (formats confirmed against real files where available —
Windows 11 Notepad TabState, Notepad++ session.xml/backups and OneDrive
ODL v3 from a real Windows 11 host; AnyDesk/TeamViewer per their widely
documented text formats):
  - Windows Notepad TabState (*.bin): "NP" magic, ULEB128 sequence, saved
    flag; saved tabs carry ULEB128-length UTF-16 path, file size, encoding,
    line-ending type, ULEB128 FILETIME and SHA-256 of the saved file; the
    tab's text is the ULEB128-length UTF-16 run that ends just before the
    trailing flag/CRC32. .0.bin/.1.bin are tiny view-state files — skipped.
  - Notepad++ backup\\<name>@<YYYY-MM-DD_HHMMSS> and session.xml.
  - AnyDesk connection_trace.txt / ad.trace / ad_svc.trace.
  - TeamViewer Connections*.txt / *_Logfile.log.
  - OneDrive *.odl (EBFGONED v3): 0xCCDDEEFF-framed records — ms epoch
    timestamp, code file, function, parameter blob. Parameter strings may
    be obfuscated by OneDrive (key in general.keystore, not collected), so
    only records whose parameters contain readable indicators are kept
    (general.keystore would be needed to decrypt the rest).

Emits `record` rows (see forensicator_records.py).
"""
import json
import os
import re
import sqlite3
import struct
import sys
import xml.etree.ElementTree as ET

from forensicator_records import (emit_error, emit_record, epoch_ms_to_iso, extract_iocs, filetime_to_iso, first,
                                  looks_binary, parse_line_timestamp, read_text, read_uleb128, utf16_strings,
                                  ascii_strings)

LINE_CAP = 5000
KEYWORDS = re.compile(
    r"\b(log(?:ged)?\s?(?:in|on|off|out)|logon|sign(?:ed)?\s?in|authenticat\w*|password|credential|session|connect(?:ed|ion)?|"
    r"disconnect\w*|incoming|outgoing|remote|transfer\w*|download\w*|upload\w*|file\s?(?:copy|sent|received)|clipboard|"
    r"quarantin\w*|detect\w*|threat|malware|block(?:ed)?|exclusion|tamper\w*|disabled?|uninstall\w*)\b",
    re.I,
)


def target_kind(target):
    t = target.lower()
    if any(x in t for x in ("anydesk", "teamviewer", "screenconnect", "rustdesk", "splashtop", "logmein")):
        return "remote_access"
    if any(x in t for x in ("onedrive", "dropbox", "google_drive", "drivefs")):
        return "cloud_sync"
    if any(x in t for x in ("crowdstrike", "sentinel", "sophos", "eset", "malwarebytes", "bitdefender", "mcafee", "trend")):
        return "security_product"
    if "notepad" in t:
        return "notepad"
    return "custom"


# ── Windows Notepad TabState ────────────────────────────────────────────────

def printable_ratio(text):
    if not text:
        return 0.0
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return ok / len(text)


def parse_tabstate(path, rel):
    if re.search(r"\.\d+\.bin$", rel, re.I):
        return  # <guid>.0.bin / .1.bin — per-tab view state, no document text
    with open(path, "rb") as fh:
        buf = fh.read()
    if len(buf) < 8 or buf[:2] != b"NP":
        emit_error(f"not a Notepad TabState file: {rel}")
        return
    try:
        _seq, o = read_uleb128(buf, 2)
        saved = buf[o] == 1
        o += 1
        saved_path = saved_size = saved_time = saved_sha256 = None
        if saved:
            plen, o = read_uleb128(buf, o)
            saved_path = buf[o:o + 2 * plen].decode("utf-16-le", errors="replace")
            o += 2 * plen
            saved_size, o = read_uleb128(buf, o)
            o += 2  # encoding, line-ending type
            ts, o = read_uleb128(buf, o)
            saved_time = filetime_to_iso(ts)
            saved_sha256 = buf[o:o + 32].hex()
            o += 32
        # The content length ULEB128 is the one whose UTF-16 run ends closest
        # to EOF (unsaved flag + CRC32 = 5 bytes on a fully-flushed tab) —
        # the selection start/end fields that precede it often hold the
        # same value (cursor at end of text), so the smallest tail wins,
        # not the first match.
        content = None
        best_tail = None
        for start in range(o, min(o + 64, len(buf))):
            try:
                length, after = read_uleb128(buf, start)
            except (IndexError, ValueError):
                break
            end = after + 2 * length
            if length > 0 and end <= len(buf) and len(buf) - end <= 64 and (best_tail is None or len(buf) - end < best_tail):
                candidate = buf[after:end].decode("utf-16-le", errors="replace")
                if printable_ratio(candidate) >= 0.85:
                    content, best_tail = candidate, len(buf) - end
    except (IndexError, ValueError) as e:
        emit_error(f"TabState parse failed for {rel}: {e}")
        return
    reconstructed = content is not None
    if content is None:
        # Unflushed edits are stored as insertion chunks rather than one
        # length-prefixed buffer (typical of .bin.bak) — recover the text
        # fragments in order instead of claiming an exact reconstruction.
        fragments = [t for _, t in utf16_strings(buf[o:], 3) if printable_ratio(t) >= 0.85]
        content = "\n".join(fragments) if fragments else None
    if content is None and not saved_path:
        return  # nothing recoverable
    text = (content or "").replace("\r", "\n")
    iocs = extract_iocs(text)
    emit_record(
        "notepad_document",
        f"Notepad tab{' (saved: ' + saved_path + ')' if saved_path else ' (unsaved)'}: {text.strip()[:200]}",
        timestamp=saved_time, path=saved_path, url=first(iocs, "urls"), ip=first(iocs, "ips"),
        sha256=saved_sha256 if saved_sha256 and saved_sha256.strip("0") else None,
        details={
            "editor": "Windows Notepad", "source_file": rel, "saved": saved, "saved_path": saved_path,
            "content_exact": reconstructed,
            "saved_file_size": saved_size, "saved_file_last_write": saved_time,
            "content_preview": text[:4000], "content_length": len(text),
            "mentions_credentials": bool(re.search(r"pass(word|wd)?|pwd|secret|api[_-]?key|token|credential", text, re.I)),
            "iocs": iocs,
        },
    )


# ── Notepad++ ───────────────────────────────────────────────────────────────

NPP_BACKUP_RE = re.compile(r"^(.*)@(\d{4}-\d{2}-\d{2})_(\d{2})(\d{2})(\d{2})$")


def parse_npp_backup(path, rel):
    text, enc = read_text(path, 16 * 1024 * 1024)
    name = os.path.basename(path)
    m = NPP_BACKUP_RE.match(name)
    ts = f"{m.group(2)}T{m.group(3)}:{m.group(4)}:{m.group(5)}" if m else None
    iocs = extract_iocs(text)
    emit_record(
        "notepad_document", f"Notepad++ unsaved '{m.group(1) if m else name}': {text.strip()[:200]}",
        timestamp=ts, url=first(iocs, "urls"), ip=first(iocs, "ips"),
        details={
            "editor": "Notepad++", "source_file": rel, "backup_name": name, "encoding": enc,
            "timestamp_note": "Notepad++ backup timestamp is local time on the source host",
            "content_preview": text[:4000], "content_length": len(text),
            "mentions_credentials": bool(re.search(r"pass(word|wd)?|pwd|secret|api[_-]?key|token|credential", text, re.I)),
            "iocs": iocs,
        },
    )


def parse_npp_session(path, rel):
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        emit_error(f"session.xml parse failed: {e}")
        return
    for f in root.iter("File"):
        filename = f.get("filename")
        if not filename:
            continue
        backup = f.get("backupFilePath") or None
        ts_hi, ts_lo = f.get("originalFileLastModifTimestampHigh"), f.get("originalFileLastModifTimestamp")
        ts = None
        try:
            if ts_hi is not None and ts_lo is not None:
                ts = filetime_to_iso((int(ts_hi) << 32) | (int(ts_lo) & 0xFFFFFFFF))
        except ValueError:
            pass
        emit_record(
            "notepad_session_file", f"Notepad++ session tab: {filename}",
            timestamp=ts, path=filename if (":\\" in filename or filename.startswith("\\\\")) else None,
            details={"editor": "Notepad++", "source_file": rel, "file": filename, "backup_file": backup,
                     "unsaved": bool(backup), "language": f.get("lang"), "encoding": f.get("encoding")},
        )


# ── Remote access tools ─────────────────────────────────────────────────────

ANYDESK_TRACE_RE = re.compile(r"(Incoming|Outgoing)\s+(\d{4}-\d{2}-\d{2}),?\s+(\d{2}:\d{2})\s+(\S+)\s+(\d+)\s+(\d+)?")
ANYDESK_LOG_IP_RE = re.compile(r"Logged in from ([0-9a-fA-F:.]+):\d+|Remote (?:address|IP)[:= ]+([0-9a-fA-F:.]+)", re.I)
ANYDESK_SESSION_RE = re.compile(r"Incoming session request:\s*(.+?)\s*\((\d+)\)|Accepting from (\d+)|Connecting to (\d+)", re.I)
TV_CONN_RE = re.compile(r"^(\d{6,12})\t([^\t]*)\t(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\t(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\t([^\t]*)\t([^\t]*)\t?(\{[^}]+\})?")


def tv_time(s):
    d, t = s.split(" ")
    dd, mm, yyyy = d.split("-")
    return f"{yyyy}-{mm}-{dd}T{t}"


def parse_remote_access(path, rel, target):
    name = os.path.basename(path).lower()
    text, _ = read_text(path)
    tool = target.split("_")[0]
    count = 0
    for line in text.splitlines():
        raw = line.rstrip()
        if not raw.strip():
            continue
        rec = None
        if "connection_trace" in name:
            m = ANYDESK_TRACE_RE.search(raw)
            if m:
                rec = ("remote_access_connection", f"AnyDesk {m.group(1).lower()} {m.group(4)} session, remote ID {m.group(5)}",
                       f"{m.group(2)}T{m.group(3)}:00", None,
                       {"tool": "AnyDesk", "direction": m.group(1).lower(), "auth": m.group(4), "remote_id": m.group(5),
                        "local_id": m.group(6), "timestamp_note": "local time on the source host"})
        elif name.startswith("connections") and name.endswith(".txt"):
            m = TV_CONN_RE.match(raw)
            if m:
                rec = ("remote_access_connection", f"TeamViewer {'incoming' if 'incoming' in name else 'outgoing'} {m.group(6)} with {m.group(1)} ({m.group(2)})",
                       tv_time(m.group(3)), None,
                       {"tool": "TeamViewer", "direction": "incoming" if "incoming" in name else "outgoing", "remote_id": m.group(1),
                        "remote_name": m.group(2), "start": tv_time(m.group(3)), "end": tv_time(m.group(4)), "local_user": m.group(5),
                        "connection_type": m.group(6), "session_guid": m.group(7), "timestamp_note": "local time on the source host"})
        if rec is None and ("anydesk" in target.lower()):
            ip = ANYDESK_LOG_IP_RE.search(raw)
            sess = ANYDESK_SESSION_RE.search(raw)
            if ip or sess:
                remote_id = next((g for g in (sess.groups() if sess else ()) if g and g.isdigit()), None)
                rec = ("remote_access_connection", f"AnyDesk: {raw.strip()[:250]}", parse_line_timestamp(raw), (ip.group(1) or ip.group(2)) if ip else None,
                       {"tool": "AnyDesk", "remote_id": remote_id, "line": raw[:2000]})
        if rec is None:
            if not (KEYWORDS.search(raw) or extract_iocs(raw)):
                continue
            iocs = extract_iocs(raw)
            rec = ("remote_access_log", f"{tool}: {raw.strip()[:250]}", parse_line_timestamp(raw), first(iocs, "ips"),
                   {"tool": tool, "line": raw[:2000], "iocs": iocs})
        kind, title, ts, ip, details = rec
        details["source_file"] = rel
        emit_record(kind, title, timestamp=ts, ip=ip or details.get("ip"), user=details.get("local_user"),
                    path=first(details.get("iocs", {}), "paths"), url=first(details.get("iocs", {}), "urls"), details=details)
        count += 1
        if count >= LINE_CAP:
            emit_error(f"{rel}: line cap ({LINE_CAP}) reached")
            break


# ── OneDrive ODL ────────────────────────────────────────────────────────────

ODL_MAGIC = b"EBFGONED"
ODL_RECORD = b"\xcc\xdd\xee\xff"


def parse_odl(path, rel):
    with open(path, "rb") as fh:
        buf = fh.read()
    if not buf.startswith(ODL_MAGIC):
        emit_error(f"{rel}: not an ODL file (or compressed .odlgz)")
        return
    version = struct.unpack_from("<I", buf, 8)[0]
    pos = buf.find(ODL_RECORD, 0x100 if len(buf) > 0x100 else 8)
    kept = 0
    while 0 <= pos < len(buf) - 32:
        try:
            ts_ms = struct.unpack_from("<Q", buf, pos + 8)[0]
            data_len = struct.unpack_from("<I", buf, pos + 24)[0]
            data = buf[pos + 32:pos + 32 + data_len]
            o = 16 + 8  # context GUID + two u32
            code_len = struct.unpack_from("<I", data, o)[0]; o += 4
            code_file = data[o:o + code_len].decode("ascii", errors="replace"); o += code_len
            o += 4  # line / flags
            func_len = struct.unpack_from("<I", data, o)[0]; o += 4
            func = data[o:o + func_len].decode("ascii", errors="replace"); o += func_len
            params = data[o:]
        except (struct.error, IndexError):
            break
        next_pos = buf.find(ODL_RECORD, pos + 32 + max(data_len, 0))
        strings = [t for _, t in ascii_strings(params, 5)] + [t for _, t in utf16_strings(params, 5)]
        joined = " | ".join(dict.fromkeys(strings))
        iocs = extract_iocs(joined)
        # Only rows whose READABLE parameters carry an indicator — on current
        # OneDrive builds most parameter strings are obfuscated with a key
        # from general.keystore (not collected), and keeping rows on the
        # function name alone just stores ciphertext (seen on a real host:
        # thousands of GeneratePathFromUrlWithScope rows, none readable).
        if iocs and joined:
            emit_record(
                "cloud_sync_event", f"OneDrive {code_file}::{func.split('::')[-1]}: {joined[:200]}",
                timestamp=epoch_ms_to_iso(ts_ms), path=first(iocs, "paths"), url=first(iocs, "urls"),
                details={"client": "OneDrive", "source_file": rel, "odl_version": version, "code_file": code_file,
                         "function": func, "params_strings": strings[:40], "iocs": iocs,
                         "note": "Parameter strings may be obfuscated by OneDrive; only readable values are shown"},
            )
            kept += 1
            if kept >= LINE_CAP:
                emit_error(f"{rel}: ODL record cap ({LINE_CAP}) reached")
                break
        if next_pos <= pos:
            break
        pos = next_pos


# ── Generic handlers ───────────────────────────────────────────────────────

def parse_sqlite(path, rel, kind_prefix):
    import shutil
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="fz-appsqlite-")
    try:
        copy = os.path.join(tmpdir, "db")
        shutil.copyfile(path, copy)
        con = sqlite3.connect(copy)
        tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
        for t in tables:
            try:
                cols = [r[1] for r in con.execute(f'pragma table_info("{t}")')]
                n = con.execute(f'select count(*) from "{t}"').fetchone()[0]
            except sqlite3.Error:
                continue
            values = []
            try:
                for row in con.execute(f'select * from "{t}" limit 2000'):
                    values.extend(str(v) for v in row if isinstance(v, str))
            except sqlite3.Error:
                pass
            iocs = extract_iocs("\n".join(values))
            emit_record(f"{kind_prefix}_database_table", f"{os.path.basename(path)} table {t} ({n} rows)",
                        path=first(iocs, "paths"), url=first(iocs, "urls"),
                        details={"source_file": rel, "table": t, "columns": cols, "row_count": n, "iocs": iocs})
        con.close()
    except sqlite3.Error as e:
        emit_error(f"{rel}: SQLite open failed: {e}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# Settings worth keeping without an indicator in the value: identity and
# location keys (OneDrive's UserFolder/UserEmail/cid/library, server names...).
INI_KEY_RE = re.compile(r"(folder|path|dir(ectory)?|user|email|account|cid|library|tenant|url|server|host|endpoint|proxy)$", re.I)


def parse_ini(path, rel, kind_prefix):
    text, _ = read_text(path, 8 * 1024 * 1024)
    section = None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith((";", "#")):
            continue
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1]
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            iocs = extract_iocs(v)
            if not iocs and not INI_KEY_RE.search(k.strip()):
                continue
            emit_record(f"{kind_prefix}_setting", f"{os.path.basename(path)}: {k.strip()} = {v.strip()[:200]}",
                        path=first(iocs, "paths"), url=first(iocs, "urls"),
                        details={"source_file": rel, "section": section, "key": k.strip(), "value": v.strip()[:2000], "iocs": iocs})


def walk_json_strings(obj, prefix="", out=None):
    out = [] if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            walk_json_strings(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:500]):
            walk_json_strings(v, f"{prefix}[{i}]", out)
    elif isinstance(obj, str):
        out.append((prefix, obj))
    return out


def parse_json(path, rel, kind_prefix):
    text, _ = read_text(path, 32 * 1024 * 1024)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return parse_text(path, rel, kind_prefix)
    count = 0
    for key, value in walk_json_strings(data):
        iocs = extract_iocs(value)
        if not iocs:
            continue
        emit_record(f"{kind_prefix}_setting", f"{os.path.basename(path)}: {key} = {value[:200]}",
                    path=first(iocs, "paths"), url=first(iocs, "urls"), ip=first(iocs, "ips"),
                    details={"source_file": rel, "key": key, "value": value[:2000], "iocs": iocs})
        count += 1
        if count >= LINE_CAP:
            break


def parse_text(path, rel, kind_prefix):
    text, _ = read_text(path)
    count = 0
    for line in text.splitlines():
        raw = line.strip()
        if not raw:
            continue
        iocs = extract_iocs(raw)
        if not iocs and not KEYWORDS.search(raw):
            continue
        emit_record(f"{kind_prefix}_log", raw[:300], timestamp=parse_line_timestamp(raw),
                    path=first(iocs, "paths"), url=first(iocs, "urls"), ip=first(iocs, "ips"),
                    sha256=first(iocs, "sha256"), sha1=first(iocs, "sha1"),
                    details={"source_file": rel, "line": raw[:2000], "iocs": iocs,
                             "timestamp_note": "timezone as written by the application"})
        count += 1
        if count >= LINE_CAP:
            emit_error(f"{rel}: line cap ({LINE_CAP}) reached")
            break


def parse_binary_strings(path, rel, kind_prefix):
    with open(path, "rb") as fh:
        buf = fh.read(64 * 1024 * 1024)
    strings = [t for _, t in ascii_strings(buf, 6)] + [t for _, t in utf16_strings(buf, 6)]
    iocs = extract_iocs("\n".join(strings))
    if iocs:
        emit_record(f"{kind_prefix}_binary", f"{os.path.basename(path)}: indicators in binary file",
                    path=first(iocs, "paths"), url=first(iocs, "urls"), ip=first(iocs, "ips"),
                    details={"source_file": rel, "iocs": iocs, "strings_scanned": len(strings)})


def main():
    if len(sys.argv) < 4:
        emit_error("usage: app-artifact-parse.py <file> <target> <relative path>")
        sys.exit(1)
    path, target, rel = sys.argv[1], sys.argv[2], sys.argv[3]
    name = os.path.basename(rel).lower()
    kind = target_kind(target)
    try:
        if kind == "notepad":
            if "notepad__" in target.lower() or "notepad++" in target.lower():
                if name == "session.xml":
                    return parse_npp_session(path, rel)
                if name == "config.xml":
                    return  # editor preferences, no evidence value
                return parse_npp_backup(path, rel)
            if name.endswith(".bin") or name.endswith(".bin.bak"):
                return parse_tabstate(path, rel)
        if kind == "remote_access":
            return parse_remote_access(path, rel, target)
        if name.endswith(".odl"):
            return parse_odl(path, rel)
        with open(path, "rb") as fh:
            head = fh.read(16)
        if head.startswith(b"SQLite format 3"):
            return parse_sqlite(path, rel, kind)
        if name.endswith(".ini") or name.endswith(".conf"):
            return parse_ini(path, rel, kind)
        if name.endswith(".json"):
            return parse_json(path, rel, kind)
        if looks_binary(path):
            return parse_binary_strings(path, rel, kind)
        return parse_text(path, rel, kind)
    except Exception as e:
        emit_error(f"{rel}: parse failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
