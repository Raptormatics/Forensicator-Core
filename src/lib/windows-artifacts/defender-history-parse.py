#!/usr/bin/env python3
"""
Microsoft Defender operational history beyond the quarantine store:

  detection_history — Scans\\History\\Service\\DetectionHistory\\<nn>\\<GUID>
      One binary file per detection. The format is undocumented; what IS
      stable (confirmed against real Windows 11 files, cross-checked against
      the same detection's 1116/1117 events) is that it is a sequence of
      typed UTF-16LE strings — threat name right after the first
      "Magic.Version:" marker, then <scheme> / <resource path> pairs
      (file, amsi, process, regkey, containerfile, webfile, ...), the
      detecting user, the process — plus two FILETIMEs: the earliest is the
      detection time (matches 1116 "Detection Time"), the latest the last
      status change/remediation (matches 1117). Parsed by structure-free
      string/timestamp carving rather than a guessed record layout.

  support_log — Support\\MPLog-*.log, MPDetection-*.log, ... (UTF-16LE text)
      MPLog is a well-known execution-evidence source: every
      "ProcessImageName: <exe>, Pid: n, ..., MaxTimeFile: <path>" line records
      a process the engine scanned, and "SDN:Issuing SDN query for <path> ...
      (sha1=..., sha2=...)" lines record file hashes. DETECTION lines record
      the threat name and resource. Repeated ProcessImageName lines are
      de-duplicated per (process, file).

Invoked as: defender-history-parse.py <file> <detection_history|support_log>
Emits `record` rows with kinds defender_detection | defender_log_detection |
defender_process_scan | defender_hash_seen | defender_exclusion | defender_tamper.
"""
import os
import re
import struct
import sys

from forensicator_records import (emit_error, emit_record, extract_iocs, filetime_to_iso, first,
                                  parse_line_timestamp, read_text, utf16_strings)

SCHEMES = ("file", "amsi", "process", "regkey", "containerfile", "webfile", "behavior", "bootsector", "folder",
           "internalamsi", "internalbehavior", "nri", "service", "startup", "taskscheduler", "wmi", "remediation")
USER_RE = re.compile(r"^[^\\/:*?\"<>|\s][^\\/:*?\"<>|]*\\[^\\/:*?\"<>|]+$")


def parse_detection_history(path):
    with open(path, "rb") as fh:
        buf = fh.read()
    strings = [t for _, t in utf16_strings(buf, 2)]
    times = []
    for off in range(0, len(buf) - 7, 4):
        iso = filetime_to_iso(struct.unpack_from("<Q", buf, off)[0])
        if iso:
            times.append(iso)
    times = sorted(set(times))

    threat = None
    resources = []
    users = []
    processes = []
    hashes = []
    for i, s in enumerate(strings):
        if s.startswith("Magic.Version"):
            continue
        if threat is None and ":" in s and "/" in s and not s.lower().startswith(SCHEMES) and "\\" not in s:
            threat = s  # e.g. Trojan:PowerShell/PSAttackTool.A
            continue
        low = s.lower()
        if low in SCHEMES and i + 1 < len(strings):
            resources.append({"scheme": low, "resource": strings[i + 1]})
            continue
        if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", s):
            hashes.append(s)
        elif USER_RE.match(s) and not s.lower().endswith((".exe", ".dll", ".ps1")):
            users.append(s)
        elif low.endswith(".exe") and ("\\" in s or "/" in s):
            processes.append(s)

    primary = next((r["resource"] for r in resources if r["scheme"] in ("file", "amsi", "process", "containerfile")), None)
    sha256 = next((h for h in hashes if len(h) == 64), None)
    sha1 = next((h for h in hashes if len(h) == 40), None)
    emit_record(
        "defender_detection", f"{threat or 'Defender detection'}: {primary or ''}".strip(),
        timestamp=times[0] if times else None,
        path=primary, user=users[0] if users else None, process=processes[0] if processes else None,
        sha256=sha256, sha1=sha1,
        details={
            "threat_name": threat, "resources": resources, "users": users, "processes": processes,
            "content_hashes": hashes, "detection_time": times[0] if times else None,
            "last_status_change": times[-1] if times else None, "all_timestamps": times,
            "detection_id": os.path.basename(path),
        },
    )


DETECTION_RE = re.compile(r"\bDETECTION(?:EVENT|_ADD#?\d*)?\s+(?:MPSOURCE_\w+\s+)?(\S+)\s+(.+)$")
PROCESS_RE = re.compile(r"ProcessImageName:\s*([^,]+),\s*Pid:\s*(\d+).*?MaxTimeFile:\s*([^,]+?)(?:,\s*EstimatedImpact|$)")
SDN_RE = re.compile(r"SDN:Issuing SDN query for (.+?)\s+\(.*?sha1=([0-9a-fA-F]{40}),\s*sha2=([0-9a-fA-F]{64})")
EXCLUSION_RE = re.compile(r"(Exclusion(?:s)?\\(?:Paths|Extensions|Processes|IpAddresses)\\?\S*|added exclusion|AddExclusion)", re.I)
TAMPER_RE = re.compile(r"(Tamper protection|DisableRealtimeMonitoring|DisableAntiSpyware|Real-?time protection (?:is )?(?:off|disabled))", re.I)


def parse_support_log(path):
    text, _ = read_text(path)
    seen_proc = set()
    emitted = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # MPLog/MPDetection timestamps are UTC (they match the DetectionHistory
        # FILETIMEs and 1116 events to the millisecond).
        ts = parse_line_timestamp(line, assume_utc=True)
        m = DETECTION_RE.search(line)
        if m:
            threat, rest = m.group(1), m.group(2)
            resources = [r for r in re.split(r"[;\s]+(?=[a-z]+:)", rest.split(" PropBag")[0].strip()) if r]
            primary = resources[0].split(":", 1)[1] if resources and ":" in resources[0] else (resources[0] if resources else None)
            emit_record("defender_log_detection", f"{threat}: {primary or ''}", timestamp=ts, path=primary,
                        details={"threat_name": threat, "resources": resources, "line": line[:2000]})
            emitted += 1
            continue
        m = PROCESS_RE.search(line)
        if m:
            proc, pid, max_file = m.group(1).strip(), m.group(2), m.group(3).strip()
            key = (proc.lower(), max_file.lower())
            if key in seen_proc:
                continue
            seen_proc.add(key)
            emit_record("defender_process_scan", f"{proc} (pid {pid}) scanned {max_file}", timestamp=ts,
                        # Not exposed as `path`: MaxTimeFile is the file that took
                        # longest to scan for this process, not something the
                        # process executed — path rules would misread it.
                        process=proc,
                        details={"pid": int(pid), "max_time_file": max_file, "line": line[:1000]})
            emitted += 1
            continue
        m = SDN_RE.search(line)
        if m:
            emit_record("defender_hash_seen", f"Cloud lookup for {m.group(1)[:300]}", timestamp=ts,
                        path=m.group(1) if ("\\" in m.group(1)) else None, sha1=m.group(2), sha256=m.group(3),
                        details={"subject": m.group(1), "line": line[:1000]})
            emitted += 1
            continue
        if EXCLUSION_RE.search(line) and "ReportError" not in line:
            iocs = extract_iocs(line)
            emit_record("defender_exclusion", line[:300], timestamp=ts, path=first(iocs, "paths"), details={"line": line[:2000]})
            emitted += 1
            continue
        if TAMPER_RE.search(line):
            emit_record("defender_tamper", line[:300], timestamp=ts, details={"line": line[:2000]})
            emitted += 1
        if emitted >= 50000:
            emit_error("Support log record cap (50000) reached — remaining lines skipped")
            break


def main():
    if len(sys.argv) < 3:
        emit_error("usage: defender-history-parse.py <file> <detection_history|support_log>")
        sys.exit(1)
    path, mode = sys.argv[1], sys.argv[2]
    try:
        if mode == "detection_history":
            parse_detection_history(path)
        else:
            parse_support_log(path)
    except Exception as e:
        emit_error(f"Defender parse failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
