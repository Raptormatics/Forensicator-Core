#!/usr/bin/env python3
"""
Hand-rolled parser for a raw $UsnJrnl:$J alternate-data-stream dump —
no suitable off-the-shelf Python library exists for parsing a
standalone extracted $J stream (as opposed to a live volume's USN
journal, which needs a mounted volume object — confirmed directly
against pyfsntfs's own volume.get_usn_change_journal() API, which
requires a full pyfsntfs.volume(), not a standalone stream file, in
this authoring sandbox). The $J stream's own on-disk format is a flat,
fully documented Microsoft structure (USN_RECORD_V2/V3 — see
https://learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
and .../ns-winioctl-usn_record_v3), stable for decades, so a small
struct-based parser is the same "write one, no library fits this exact
shape" precedent lnk-parse.py sets for .customDestinations-ms and
jumplist-parse.py sets for the DestList stream.

Reads sequentially from the start of the file, one record at a time:
unpack the fixed 60-byte (V2) or 76-byte (V3) header to learn
RecordLength and FileNameOffset/FileNameLength, extract the UTF-16LE
filename, decode the Reason bitmask into named flags, then advance by
RecordLength — NEVER by a declared/assumed record count, since nothing
in this format declares a total count (same "advance on the format's
own self-reported length" lesson this codebase's other hand-rolled
parsers already encode). $UsnJrnl:$J is a sparse file — unwritten
regions read back as zeros — so a RecordLength of 0 means "no more real
records" and ends the read cleanly, not an error.

Byte layout (both verified by direct arithmetic against the documented
struct definitions, not assumed):
  V2 (MajorVersion 2): RecordLength@0(4) MajorVersion@4(2) MinorVersion@6(2)
    FileReferenceNumber@8(8) ParentFileReferenceNumber@16(8) Usn@24(8)
    TimeStamp@32(8) Reason@40(4) SourceInfo@44(4) SecurityId@48(4)
    FileAttributes@52(4) FileNameLength@56(2) FileNameOffset@58(2) -> 60 bytes
  V3 (MajorVersion 3, 128-bit file IDs — ReFS, or NTFS in some configs):
    RecordLength@0(4) MajorVersion@4(2) MinorVersion@6(2)
    FileReferenceNumber@8(16) ParentFileReferenceNumber@24(16) Usn@40(8)
    TimeStamp@48(8) Reason@56(4) SourceInfo@60(4) SecurityId@64(4)
    FileAttributes@68(4) FileNameLength@72(2) FileNameOffset@74(2) -> 76 bytes

Invoked as: usnjrnl-parse.py <j_stream_file_path>

Emits one JSON object per line to stdout:
  {"type": "usn_entry", "usn", "file_reference_number", "parent_file_reference_number",
   "timestamp", "reason": [...], "file_name", "file_attributes", "source_info"}
  {"type": "error", "message": str}                — unrecoverable failure partway through
"""
import sys
import json
import struct
from datetime import datetime, timedelta

V2_HEADER_SIZE = 60
V3_HEADER_SIZE = 76

# (bit, name) — from winioctl.h's USN_REASON_* constants, stable public
# Win32 API surface unchanged for decades.
USN_REASON_FLAGS = [
    (0x00000001, "DATA_OVERWRITE"),
    (0x00000002, "DATA_EXTEND"),
    (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"),
    (0x00000020, "NAMED_DATA_EXTEND"),
    (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"),
    (0x00000200, "FILE_DELETE"),
    (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"),
    (0x00001000, "RENAME_OLD_NAME"),
    (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"),
    (0x00008000, "BASIC_INFO_CHANGE"),
    (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"),
    (0x00040000, "ENCRYPTION_CHANGE"),
    (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"),
    (0x00200000, "STREAM_CHANGE"),
    (0x00400000, "TRANSACTED_CHANGE"),
    (0x00800000, "INTEGRITY_CHANGE"),
    (0x80000000, "CLOSE"),
]


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def decode_reason(reason):
    return [name for bit, name in USN_REASON_FLAGS if reason & bit]


def filetime_to_iso(raw_int):
    """Same FILETIME-to-UTC-ISO fix as every other parser in this feature
    (see prefetch-parse.py/registry-parse.py's own versions of this)."""
    if not raw_int or raw_int <= 0:
        return None
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=raw_int / 10)).isoformat() + "Z"
    except Exception:
        return None


def decode_record(record):
    """Decodes one USN_RECORD_V2 or V3 buffer (already sliced to its own
    RecordLength) into a dict, or raises on malformed input."""
    major_version = struct.unpack_from("<H", record, 4)[0]

    if major_version >= 3:
        file_ref = int.from_bytes(record[8:24], "little")
        parent_ref = int.from_bytes(record[24:40], "little")
        usn, timestamp_raw, reason, source_info, _security_id, file_attributes = \
            struct.unpack_from("<qqIIII", record, 40)
        name_length, name_offset = struct.unpack_from("<HH", record, 72)
    else:
        file_ref = int.from_bytes(record[8:16], "little")
        parent_ref = int.from_bytes(record[16:24], "little")
        usn, timestamp_raw, reason, source_info, _security_id, file_attributes = \
            struct.unpack_from("<qqIIII", record, 24)
        name_length, name_offset = struct.unpack_from("<HH", record, 56)

    if name_offset and 0 <= name_offset and name_offset + name_length <= len(record):
        file_name = record[name_offset:name_offset + name_length].decode("utf-16-le", errors="replace")
    else:
        file_name = None

    return {
        "type": "usn_entry",
        "usn": usn,
        "file_reference_number": str(file_ref),
        "parent_file_reference_number": str(parent_ref),
        "timestamp": filetime_to_iso(timestamp_raw),
        "reason": decode_reason(reason),
        "file_name": file_name,
        "file_attributes": file_attributes,
        "source_info": source_info,
    }


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: usnjrnl-parse.py <j_stream_file_path>"})
        sys.exit(1)
    j_path = sys.argv[1]

    try:
        with open(j_path, "rb") as f:
            data = f.read()
    except Exception as e:
        emit({"type": "error", "message": f"failed to open $UsnJrnl:$J stream: {e}"})
        sys.exit(1)

    offset = 0
    size = len(data)
    record_count = 0

    while offset + 4 <= size:
        record_length = struct.unpack_from("<I", data, offset)[0]
        if record_length == 0:
            break  # sparse-file zero padding (or an empty/truncated file) — end of real records
        if offset + record_length > size:
            emit({"type": "error", "message": f"record at offset {offset} claims length {record_length}, which runs past end of file ({size}) — stopping"})
            break
        if record_length < V2_HEADER_SIZE:
            emit({"type": "error", "message": f"record at offset {offset} has implausible length {record_length} (below the minimum {V2_HEADER_SIZE}-byte header) — stopping"})
            break

        record = data[offset:offset + record_length]
        try:
            emit(decode_record(record))
            record_count += 1
        except Exception as e:
            emit({"type": "error", "message": f"failed to decode record at offset {offset}: {e}"})

        offset += record_length

    if record_count == 0:
        emit({"type": "error", "message": "no USN records decoded — file may be empty, fully sparse, or not a valid $UsnJrnl:$J dump"})


if __name__ == "__main__":
    main()
