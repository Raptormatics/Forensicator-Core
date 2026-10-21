#!/usr/bin/env python3
"""
NTFS $LogFile — carves $FILE_NAME attribute bodies out of the transaction
log's redo/undo data.

$LogFile's restart/record-page structures are documented, but its redo/undo
payloads are raw MFT/index fragments whose layout depends on the operation
code — the dependable, analyst-useful content is the $FILE_NAME attribute
bodies those fragments contain (file creates, renames and index entries
being added/removed). Each body has a fixed layout (MS-FSCC / NTFS
documentation): parent file reference (8), four FILETIMEs — created,
modified, MFT-entry modified, accessed (32), allocated size (8), real size
(8), flags (4), reparse value (4), name length in characters (1), namespace
(1: POSIX/Win32/DOS/Win32&DOS), then the UTF-16LE name.

A candidate is accepted only if all four timestamps fall in a plausible
range (1980..2041), the namespace is 0-3, and the name is a valid Windows
file name — then de-duplicated on (parent, name, timestamps). Because
$LogFile wraps every few hours on a busy volume, these rows describe recent
file-system activity, including files since deleted or renamed. Rows are
emitted as `record` kind `logfile_filename`.

Invoked as: logfile-parse.py <$LogFile>
"""
import re
import struct
import sys

from forensicator_records import emit_error, emit_record, filetime_to_iso

FT_MIN = 119600064000000000   # 1980-01-01
FT_MAX = 139000000000000000   # ~2041
INVALID_NAME = re.compile(r'[\x00-\x1f"*/:<>?\\|]')
NAMESPACES = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32&DOS"}
CAP = 200000
CHUNK = 64 * 1024 * 1024


def scan(buf, base, seen, emitted):
    n = len(buf)
    # FILE_NAME bodies are 8-byte aligned inside attribute records.
    for off in range(0, n - 66, 8):
        times = struct.unpack_from("<4Q", buf, off + 8)
        if not all(FT_MIN <= t <= FT_MAX for t in times):
            continue
        name_len = buf[off + 64]
        ns = buf[off + 65]
        if name_len == 0 or ns > 3 or off + 66 + 2 * name_len > n:
            continue
        try:
            name = buf[off + 66:off + 66 + 2 * name_len].decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if INVALID_NAME.search(name) or name.strip() != name or name in (".", ".."):
            continue
        parent_raw = struct.unpack_from("<Q", buf, off)[0]
        parent_entry = parent_raw & 0xFFFFFFFFFFFF
        parent_seq = parent_raw >> 48
        if parent_entry == 0 or parent_entry > 0xFFFFFFFF:
            continue
        alloc, real, flags = struct.unpack_from("<QQI", buf, off + 40)
        key = (parent_raw, name, times)
        if key in seen:
            continue
        seen.add(key)
        created, modified, mft_modified, accessed = (filetime_to_iso(t) for t in times)
        emit_record(
            "logfile_filename", name, timestamp=modified, path=name,
            details={
                "name": name, "namespace": NAMESPACES.get(ns), "parent_entry": parent_entry, "parent_sequence": parent_seq,
                "created": created, "modified": modified, "mft_modified": mft_modified, "accessed": accessed,
                "allocated_size": alloc, "real_size": real, "flags": flags, "logfile_offset": base + off,
                "possible_timestomp": bool(times[0] > times[2]),
            },
        )
        emitted[0] += 1
        if emitted[0] >= CAP:
            return False
    return True


def main():
    if len(sys.argv) < 2:
        emit_error("usage: logfile-parse.py <$LogFile>")
        sys.exit(1)
    seen = set()
    emitted = [0]
    try:
        with open(sys.argv[1], "rb") as fh:
            head = fh.read(4)
            if head not in (b"RSTR", b"CHKD"):
                emit_error(f"no $LogFile restart-page signature (got {head!r}) — carving anyway")
            fh.seek(0)
            base = 0
            carry = b""
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                buf = carry + chunk
                if not scan(buf, base - len(carry), seen, emitted):
                    emit_error(f"record cap ({CAP}) reached")
                    break
                # Keep an aligned tail so a body straddling the boundary is seen once.
                keep = 600
                carry = buf[-keep:]
                base += len(chunk)
    except Exception as e:
        emit_error(f"$LogFile parse failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
