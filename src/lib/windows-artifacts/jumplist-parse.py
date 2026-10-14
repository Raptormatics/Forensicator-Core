#!/usr/bin/env python3
"""
Parses a .automaticDestinations-ms Jump List via olefile (OLE/Structured
Storage container reader) + LnkParse3 (each numbered stream is itself a
complete LNK structure — confirmed by cross-checking forensics.wiki, the
EnCase/OpenText Link File & Jump List Parser description, and live-testing
against real sample files from plaso's test corpus: every numbered
stream's full length was consumed exactly by LnkParse3 with zero leftover
bytes). Both libraries installed pure-pip into the existing
`.venvs/winartifacts` venv, no system library dependency.

The `DestList` stream (an access-order/metadata index, not present at all
in a .customDestinations-ms) is a 32-byte header followed by variable-size
entry records, PER libyal's own dtformats "Jump lists format"
specification (https://github.com/libyal/dtformats, GFDL — the
authoritative public spec; Joachim Metz, libyal's author). Confirmed field
offsets, both via the spec and live-tested against real automaticDestinations-ms
samples:
  header: format_version(4)@0, number_of_entries(4)@4, number_of_pinned_entries(4)@8
  entry (format version 1 — Windows 7): fixed portion is 114 bytes, path at 114
  entry (format version 2+ — Windows 10): fixed portion is 132 bytes
    (16 extra bytes inserted before path_size vs. version 1), path at 130,
    followed by 4 bytes of alignment padding AFTER the path
  common to both: hostname/NetBIOS(16)@72, entry_number(4)@88 (cross-refs
    the numbered OLE stream this metadata belongs to), last_modified
    FILETIME(8)@100, pin_status(4)@108 (-1 = unpinned, >=0 = pinned
    position), path_size(2)@(112 or 128), path@(114 or 130)
The DestList stream's own entry order is itself MRU-ordered — confirmed
against real sample data (position 0 is the most-recently-used entry,
matching how DFIR tools like JLECmd report it) — used directly as
`access_rank` below, not a guess.

Invoked as: jumplist-parse.py <file_path>

Emits one JSON object per line to stdout:
  {"type": "not_installed"}                        — olefile or LnkParse3 missing, degrade gracefully
  {"type": "jumplist_entry", ...fields}
  {"type": "error", "message": str}                 — unrecoverable failure for this file
"""
import sys
import json
import struct


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def _iso(dt):
    if dt is None:
        return None
    try:
        s = dt.isoformat()
        return s if dt.tzinfo is not None else s + "Z"
    except Exception:
        return None


def filetime_to_iso(raw_int):
    """Decodes an integer Windows FILETIME (100ns intervals since
    1601-01-01 UTC) into a UTC ISO 8601 string."""
    from datetime import datetime, timedelta
    if not raw_int:
        return None
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=raw_int / 10)).isoformat() + "Z"
    except Exception:
        return None


def parse_destlist(dest_bytes):
    """Returns a dict keyed by entry_number (as a lowercase-hex string,
    matching the OLE stream naming convention: "^[1-9a-f][0-9a-f]*$") ->
    {"access_rank", "pinned", "machine_name", "last_accessed"}."""
    result = {}
    if len(dest_bytes) < 12:
        return result
    version, _num_entries, _num_pinned = struct.unpack("<III", dest_bytes[0:12])

    offset = 32
    rank = 0
    while offset + 114 <= len(dest_bytes):
        machine_name = dest_bytes[offset + 72:offset + 88].split(b"\x00")[0].decode("ascii", errors="replace")
        entry_number = struct.unpack("<I", dest_bytes[offset + 88:offset + 92])[0]
        last_modified_filetime = struct.unpack("<Q", dest_bytes[offset + 100:offset + 108])[0]
        pin_status = struct.unpack("<i", dest_bytes[offset + 108:offset + 112])[0]

        if version == 1:
            path_size_off, path_off = offset + 112, offset + 114
        else:
            path_size_off, path_off = offset + 128, offset + 130
        if path_size_off + 2 > len(dest_bytes):
            break
        path_size = struct.unpack("<H", dest_bytes[path_size_off:path_size_off + 2])[0]
        path_bytes_len = path_size * 2
        entry_end = path_off + path_bytes_len
        if entry_end > len(dest_bytes):
            break

        result[f"{entry_number:x}"] = {
            "access_rank": rank,
            "pinned": pin_status != -1,
            "machine_name": machine_name or None,
            "last_accessed": filetime_to_iso(last_modified_filetime),
        }

        entry_total = entry_end - offset
        if version != 1:
            entry_total += 4  # alignment padding after the path
        offset += entry_total
        rank += 1

    return result


def build_entry_from_lnk(lnk, res, stream_name, destlist_meta):
    link_info = res.get("link_info") or {}
    loc_info = link_info.get("location_info") or {}
    data = res.get("data") or {}

    location = link_info.get("location", "")
    target_path = None
    if "Local" in location:
        base = link_info.get("local_base_path") or link_info.get("local_base_path_unicode")
        suffix = link_info.get("common_path_suffix") or link_info.get("common_path_suffix_unicode") or ""
        if base:
            target_path = base + suffix
    elif "Network" in location:
        net_name = loc_info.get("net_name") or loc_info.get("net_name_unicode")
        suffix = link_info.get("common_path_suffix") or link_info.get("common_path_suffix_unicode") or ""
        if net_name:
            target_path = net_name + ("\\" + suffix if suffix and not suffix.startswith("\\") else suffix)
    if not target_path and data.get("relative_path"):
        target_path = data["relative_path"]
    if not target_path:
        items = (res.get("target") or {}).get("items") or []
        for item in reversed(items):
            if isinstance(item, dict):
                name = item.get("primary_name") or item.get("name") or item.get("value")
                if name:
                    target_path = str(name)
                    break

    meta = destlist_meta.get(stream_name, {})
    return {
        "type": "jumplist_entry",
        "stream_number": stream_name,
        "target_path": target_path,
        "arguments": data.get("command_line_arguments"),
        "working_directory": data.get("working_directory"),
        "last_accessed": meta.get("last_accessed"),
        "access_rank": meta.get("access_rank"),
        "pinned": meta.get("pinned"),
        "machine_name": meta.get("machine_name"),
    }


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: jumplist-parse.py <file_path>"})
        sys.exit(1)
    file_path = sys.argv[1]

    try:
        import olefile
        import LnkParse3
    except ImportError:
        emit({"type": "not_installed"})
        sys.exit(0)

    try:
        ole = olefile.OleFileIO(file_path)
    except Exception as e:
        emit({"type": "error", "message": f"failed to open OLE container: {e}"})
        sys.exit(1)

    try:
        streams = ole.listdir()
    except Exception as e:
        emit({"type": "error", "message": f"failed to list OLE streams: {e}"})
        sys.exit(1)

    destlist_meta = {}
    try:
        if ole.exists("DestList"):
            dest_bytes = ole.openstream("DestList").read()
            destlist_meta = parse_destlist(dest_bytes)
    except Exception as e:
        emit({"type": "error", "message": f"DestList parse failed (continuing without its metadata): {e}"})

    for entry in streams:
        stream_name = "/".join(entry)
        if stream_name.lower() == "destlist":
            continue
        try:
            stream_bytes = ole.openstream(entry).read()
        except Exception as e:
            emit({"type": "error", "message": f"failed to read stream {stream_name}: {e}"})
            continue
        try:
            lnk = LnkParse3.lnk_file(indata=stream_bytes)
            res = lnk.get_json(get_all=True)
            emit(build_entry_from_lnk(lnk, res, stream_name.lower(), destlist_meta))
        except Exception as e:
            emit({"type": "error", "message": f"stream {stream_name}: LNK parse failed: {e}"})


if __name__ == "__main__":
    main()
