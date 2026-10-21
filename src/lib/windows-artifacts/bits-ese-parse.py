#!/usr/bin/env python3
"""
BITS job database, Windows 10+ ESE format (qmgr.db) — the legacy
qmgr0.dat/qmgr1.dat format is handled by bits-parse.py (bits_parser).

Two passes, both emitting the same `bits_job` rows bits-parse.py does (so
they land in the existing BitsJobEntry table and existing BITS rules):

1. Live records, via pyesedb (when installed — same system-python tier as
   srum-parse.py): the Jobs and Files tables each hold an Id and an opaque
   Blob. The blob layout is undocumented, but its strings are UTF-16LE and
   stable in meaning — a Files blob holds destination path, source URL and
   the BIT*.tmp temporary name; a Jobs blob holds the job name, description
   and (for notify-command persistence) the command line.

2. Carving the raw database file for (destination, URL, BIT*.tmp) string
   triples — confirmed against a real Windows 11 qmgr.db whose live tables
   were empty but whose free pages still held dozens of completed/deleted
   transfers (Office, OneDrive, Adobe, OEM updater downloads). Attackers
   delete BITS jobs after use, so these are flagged is_carved and feed the
   existing "Recovered BITS Job Evidence" rule. Triples already seen in a
   live record are not repeated.

Invoked as: bits-ese-parse.py <qmgr.db>
"""
import re
import sys

from forensicator_records import emit, emit_error, utf16_strings

URL_RE = re.compile(r"^(?:https?|ftp|smb|file)://", re.I)
PATH_RE = re.compile(r"^(?:[A-Za-z]:\\|\\\\)")
TMP_RE = re.compile(r"\\BIT[0-9A-F]{1,8}\.tmp$", re.I)
WINDOW = 1024  # bytes between the strings of one file-transfer record


def bits_row(job_id=None, name=None, desc=None, cmd=None, dest=None, src=None, tmp=None, carved=False):
    return {"type": "bits_job", "job_id": job_id, "name": name, "desc": desc, "cmd": cmd, "sid": None,
            "job_type": None, "priority": None, "state": None, "ctime": None, "mtime": None,
            "dest_fn": dest, "src_fn": src, "tmp_fn": tmp, "download_size_bytes": None,
            "transfer_size_bytes": None, "is_carved": carved}


def triples(strings):
    """(dest, url, tmp) from an ordered [(offset, text)] list."""
    out = []
    for i, (off, text) in enumerate(strings):
        if not URL_RE.match(text):
            continue
        dest = next((t for o, t in reversed(strings[max(0, i - 3):i]) if PATH_RE.match(t) and off - o <= WINDOW), None)
        tmp = next((t for o, t in strings[i + 1:i + 4] if TMP_RE.search(t) and o - off <= WINDOW), None)
        if dest or tmp:
            out.append((dest, text, tmp))
    return out


def live_records(path, seen):
    try:
        import pyesedb
    except ImportError:
        emit_error("pyesedb not installed — live qmgr.db records skipped, carving only")
        return
    f = pyesedb.file()
    f.open(path)
    try:
        for i in range(f.get_number_of_tables()):
            table = f.get_table(i)
            tname = table.get_name()
            if tname not in ("Jobs", "Files"):
                continue
            for r in range(table.get_number_of_records()):
                rec = table.get_record(r)
                job_id, blob = None, b""
                for c in range(rec.get_number_of_values()):
                    col = rec.get_column_name(c)
                    try:
                        data = rec.get_value_data(c)
                    except Exception:
                        data = None
                    if data is None:
                        continue
                    if col == "Id" and len(data) == 16:
                        import uuid
                        job_id = str(uuid.UUID(bytes_le=bytes(data)))
                    elif col == "Blob":
                        blob = bytes(data)
                strings = utf16_strings(blob, 3)
                if tname == "Files":
                    for dest, src, tmp in triples(strings) or [(None, None, None)]:
                        seen.add((dest, src, tmp))
                        emit(bits_row(job_id=job_id, dest=dest, src=src, tmp=tmp))
                else:
                    texts = [t for _, t in strings]
                    cmd = next((t for t in texts if re.search(r"\.(exe|cmd|bat|ps1|vbs|js)\b", t, re.I)), None)
                    for dest, src, tmp in triples(strings) or [(None, None, None)]:
                        seen.add((dest, src, tmp))
                        emit(bits_row(job_id=job_id, name=texts[0] if texts else None,
                                      desc=texts[1] if len(texts) > 1 else None, cmd=cmd, dest=dest, src=src, tmp=tmp))
    finally:
        f.close()


def carve(path, seen):
    with open(path, "rb") as fh:
        buf = fh.read()
    for dest, src, tmp in triples(utf16_strings(buf, 6)):
        key = (dest, src, tmp)
        if key in seen:
            continue
        seen.add(key)
        emit(bits_row(dest=dest, src=src, tmp=tmp, carved=True))


def main():
    if len(sys.argv) < 2:
        emit_error("usage: bits-ese-parse.py <qmgr.db>")
        sys.exit(1)
    seen = set()
    try:
        live_records(sys.argv[1], seen)
    except Exception as e:
        emit_error(f"qmgr.db ESE open failed ({e}) — falling back to carving only")
    try:
        carve(sys.argv[1], seen)
    except Exception as e:
        emit_error(f"qmgr.db carving failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
