#!/usr/bin/env python3
"""
Parses a single Recycle Bin $I metadata file. No library fits this exact
shape (same "hand-roll it" precedent as usnjrnl-parse.py) — the format is
small and has exactly two documented versions, widely corroborated across
independent practitioner write-ups (no single authoritative Microsoft
spec exists, flagged plainly):

Version 1 (pre-Windows 10 — Vista/7/8.1): fixed 544-byte record.
  offset 0x00 (8 bytes): version marker, int64 LE == 1
  offset 0x08 (8 bytes): original file size, int64 LE
  offset 0x10 (8 bytes): deletion time, Windows FILETIME, int64 LE
  offset 0x18 (520 bytes): original file path, fixed-width UTF-16LE
    (260 WCHARs incl. terminating null — MAX_PATH)

Version 2 (Windows 10+): variable-length record.
  offset 0x00 (8 bytes): version marker, int64 LE == 2
  offset 0x08 (8 bytes): original file size, int64 LE
  offset 0x10 (8 bytes): deletion time, Windows FILETIME, int64 LE
  offset 0x18 (4 bytes): path length, int32 LE, in UTF-16 characters
    (NOT including the terminating null)
  offset 0x1C (pathLength*2 bytes): original file path, UTF-16LE

The version marker at offset 0 is read first and used to pick which
layout applies — not assumed from file size alone, since v1's size is
fixed but a corrupt/truncated v2 file could coincidentally match it.

Invoked as: recyclebin-parse.py <i_file_path>

Emits one JSON object per line to stdout:
  {"type": "recyclebin_entry", "format_version", "original_path",
   "deleted_time", "file_size_bytes"}
  {"type": "error", "message": str}
"""
import sys
import json
import struct
from datetime import datetime, timedelta


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def filetime_to_iso(raw_int):
    if not raw_int or raw_int <= 0:
        return None
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=raw_int / 10)).isoformat() + "Z"
    except Exception:
        return None


def parse_v1(data):
    if len(data) < 0x18 + 520:
        raise ValueError(f"truncated v1 record: {len(data)} bytes, need {0x18 + 520}")
    file_size = struct.unpack_from("<q", data, 0x08)[0]
    deleted_filetime = struct.unpack_from("<q", data, 0x10)[0]
    path_bytes = data[0x18:0x18 + 520]
    path = path_bytes.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
    return file_size, deleted_filetime, path


def parse_v2(data):
    if len(data) < 0x1C:
        raise ValueError(f"truncated v2 header: {len(data)} bytes, need at least {0x1C}")
    file_size = struct.unpack_from("<q", data, 0x08)[0]
    deleted_filetime = struct.unpack_from("<q", data, 0x10)[0]
    path_len_chars = struct.unpack_from("<i", data, 0x18)[0]
    path_byte_len = path_len_chars * 2
    if path_len_chars < 0 or len(data) < 0x1C + path_byte_len:
        raise ValueError(f"v2 path length {path_len_chars} exceeds available data ({len(data) - 0x1C} bytes)")
    path = data[0x1C:0x1C + path_byte_len].decode("utf-16-le", errors="ignore")
    return file_size, deleted_filetime, path


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: recyclebin-parse.py <i_file_path>"})
        sys.exit(1)
    i_path = sys.argv[1]

    try:
        with open(i_path, "rb") as f:
            data = f.read()
    except Exception as e:
        emit({"type": "error", "message": f"failed to read $I file: {e}"})
        sys.exit(1)

    try:
        if len(data) < 8:
            emit({"type": "error", "message": f"file too small to contain a version marker: {len(data)} bytes"})
            sys.exit(1)

        version = struct.unpack_from("<q", data, 0x00)[0]

        if version == 1:
            file_size, deleted_filetime, path = parse_v1(data)
        elif version == 2:
            file_size, deleted_filetime, path = parse_v2(data)
        else:
            emit({"type": "error", "message": f"unrecognized $I format version marker: {version}"})
            sys.exit(1)

        emit({
            "type": "recyclebin_entry",
            "format_version": version,
            "original_path": path,
            "deleted_time": filetime_to_iso(deleted_filetime),
            "file_size_bytes": file_size if file_size >= 0 else None,
        })
    except Exception as e:
        emit({"type": "error", "message": str(e)})


if __name__ == "__main__":
    main()
