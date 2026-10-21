#!/usr/bin/env python3
"""
Parses a standalone, extracted $MFT file via pyfsntfs
(https://github.com/libyal/libfsntfs), the Python bindings for libyal's
libfsntfs C library — installed as a system package (see
deploy/install-winartifacts-deps.sh), not pip-installed into the
winartifacts venv, since it links against a compiled C library — same
split as pyscca/Prefetch (see getWinArtifactsSystemPythonPath()'s own
doc comment).

Confirmed directly against a real libfsntfs-python install in the
authoring sandbox (pip install libfsntfs-python; no genuine $MFT sample
was available to test against, so the API surface below is confirmed
present and correctly shaped, not confirmed against real decoded
values — flagged plainly, not claimed as more than it is):
pyfsntfs.mft_metadata_file(), .open(path), .get_number_of_file_entries(),
.get_file_entry(index) -> object with .get_name(), .get_creation_time(),
.get_modification_time(), .get_access_time(),
.get_entry_modification_time(), .is_allocated(), .size,
.file_attribute_flags, .get_number_of_alternate_data_streams(),
.parent_file_reference.

Invoked as: mft-parse.py <mft_file_path>

Two-pass design, required because path resolution needs the WHOLE table
up front (a child can be enumerated before or after its own parent — MFT
entry order gives no ordering guarantee either way):
  1. Read every entry's raw name/parent/metadata into memory once.
  2. Walk each entry's parent chain (memoized — each entry's resolved
     path is computed once and reused by its own children) to build a
     full path, then emit one JSON line per entry.

MFT entry 5 is always the volume's root directory on every NTFS volume
(0=$MFT, 1=$MFTMirr, 2=$LogFile, 3=$Volume, 4=$AttrDef, 5=root, ...) —
a fixed, documented NTFS convention, not something that varies per
volume; used here as the path-resolution base case.

parent_file_reference's low 48 bits are the parent's own MFT entry
number (the high 16 bits are a sequence number, not part of the index) —
this is the documented NTFS MFT_SEGMENT_REFERENCE/FILE_REFERENCE layout
(MS-FSCC 2.1.5), not pyfsntfs-specific; this script decodes it directly
rather than trusting a convenience accessor, since none was confirmed
present on the file_entry object itself beyond the raw reference value.
This entry's OWN number is simply its index in get_file_entry(i) — by
definition of what the MFT physically is (a flat array where position i
IS entry i) — not derived from file_reference at all, avoiding any
ambiguity there.

Emits one JSON object per line to stdout:
  {"type": "not_installed"}                                   — pyfsntfs missing, degrade gracefully
  {"type": "mft_entry", "mft_entry_number", "sequence_number", "name", "path",
   "parent_entry_number", "is_allocated", "is_directory", "creation_time",
   "modification_time", "access_time", "entry_modification_time",
   "file_size", "has_alternate_data_streams"}
  {"type": "error", "message": str}                             — unrecoverable failure for this file
"""
import sys
import json

ROOT_ENTRY_NUMBER = 5
MAX_PARENT_CHAIN_DEPTH = 128  # guards against a corrupt/cyclic parent chain rather than looping forever

FILE_ATTRIBUTE_DIRECTORY = 0x10


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def to_utc_iso(t):
    """Same fix as prefetch-parse.py's to_utc_iso()/registry-parse.py's
    filetime_to_iso() — pyfsntfs returns naive datetimes for NTFS
    timestamps (always UTC by definition), and a naive .isoformat() with
    no "Z" gets silently reinterpreted as local time by a JS consumer."""
    if t is None:
        return None
    try:
        if getattr(t, "year", 1601) <= 1601:
            return None
        return t.isoformat() + "Z"
    except Exception:
        return None


def decode_parent_entry_number(parent_file_reference):
    if parent_file_reference is None:
        return None
    try:
        return int(parent_file_reference) & 0xFFFFFFFFFFFF
    except Exception:
        return None


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: mft-parse.py <mft_file_path>"})
        sys.exit(1)
    mft_path = sys.argv[1]

    try:
        import pyfsntfs
    except ImportError:
        emit({"type": "not_installed"})
        sys.exit(0)

    # A fragmented $MFT copied as one contiguous range only contains real
    # records up to the end of its first run (see mft_fragmentation()) —
    # seen on a real Windows 11 host: ~205k of ~1.42M records, the rest of
    # the 1.4 GB file was unrelated disk data. Parse just the valid part and
    # say so, instead of failing or emitting garbage entries.
    try:
        frag = mft_fragmentation(mft_path)
    except Exception:
        frag = None
    if frag and frag[0] > 1:
        runs, first_records, total_records = frag
        emit({"type": "error", "message": (
            f"This $MFT is fragmented on disk ({runs} data runs) but the copy only holds its first run: "
            f"records 0-{first_records - 1} of {total_records} are real, the rest of the file is unrelated disk data "
            f"and was not parsed. Re-collect the $MFT following its data runs to get the remaining "
            f"{total_records - first_records} records.")})
        parse_raw(mft_path, limit=first_records)
        return

    try:
        mft_file = pyfsntfs.mft_metadata_file()
        mft_file.open(mft_path)
    except Exception as e:
        # libfsntfs reads the whole MFT entry list up front and refuses the
        # file if ANY record is damaged — seen on a real live-acquired
        # 1.4 GB Windows 11 $MFT (one bad record, entry 798530, failed the
        # entire file). Fall back to parsing FILE records directly, skipping
        # bad ones, rather than losing the whole $MFT.
        emit({"type": "error", "message": f"pyfsntfs could not open the $MFT ({str(e)[:300]}) — using the raw FILE-record parser instead"})
        parse_raw(mft_path)
        return

    try:
        count = mft_file.get_number_of_file_entries()
    except Exception as e:
        emit({"type": "error", "message": f"failed to read file entry count: {e}"})
        return

    # Pass 1 — read every entry's raw data once.
    raw = {}
    for i in range(count):
        try:
            fe = mft_file.get_file_entry(i)
        except Exception as e:
            emit({"type": "error", "message": f"failed to read MFT entry {i}: {e}"})
            continue

        try:
            name = fe.get_name() or ""
        except Exception:
            name = ""

        try:
            parent_entry_number = decode_parent_entry_number(fe.parent_file_reference)
        except Exception:
            parent_entry_number = None

        try:
            is_allocated = bool(fe.is_allocated())
        except Exception:
            is_allocated = False

        try:
            attr_flags = fe.file_attribute_flags or 0
        except Exception:
            attr_flags = 0
        is_directory = bool(attr_flags & FILE_ATTRIBUTE_DIRECTORY)

        try:
            creation_time = to_utc_iso(fe.get_creation_time())
        except Exception:
            creation_time = None
        try:
            modification_time = to_utc_iso(fe.get_modification_time())
        except Exception:
            modification_time = None
        try:
            access_time = to_utc_iso(fe.get_access_time())
        except Exception:
            access_time = None
        try:
            entry_modification_time = to_utc_iso(fe.get_entry_modification_time())
        except Exception:
            entry_modification_time = None

        try:
            file_size = int(fe.size) if fe.size is not None else None
        except Exception:
            file_size = None

        try:
            ads_count = fe.get_number_of_alternate_data_streams()
            has_ads = bool(ads_count and ads_count > 0)
        except Exception:
            has_ads = False

        try:
            sequence_number = int(fe.file_reference >> 48) if fe.file_reference is not None else None
        except Exception:
            sequence_number = None

        raw[i] = {
            "name": name,
            "parent_entry_number": parent_entry_number,
            "is_allocated": is_allocated,
            "is_directory": is_directory,
            "sequence_number": sequence_number,
            "creation_time": creation_time,
            "modification_time": modification_time,
            "access_time": access_time,
            "entry_modification_time": entry_modification_time,
            "file_size": file_size,
            "has_alternate_data_streams": has_ads,
        }

    # Pass 2 — resolve paths via memoized parent-chain walk, then emit.
    path_cache = {ROOT_ENTRY_NUMBER: ""}

    def resolve_path(entry_number, depth=0):
        if entry_number in path_cache:
            return path_cache[entry_number]
        if depth > MAX_PARENT_CHAIN_DEPTH or entry_number not in raw:
            return None

        entry = raw[entry_number]
        parent_number = entry["parent_entry_number"]
        if parent_number is None or parent_number == entry_number:
            # No resolvable parent (orphaned, or a self-referential root
            # variant) — the entry's own name is the best we can do.
            resolved = entry["name"] or None
            path_cache[entry_number] = resolved
            return resolved

        parent_path = resolve_path(parent_number, depth + 1)
        if parent_path is None:
            resolved = entry["name"] or None
        elif entry["name"]:
            resolved = f"{parent_path}\\{entry['name']}" if parent_path else entry["name"]
        else:
            resolved = parent_path or None

        path_cache[entry_number] = resolved
        return resolved

    for entry_number, entry in raw.items():
        emit({
            "type": "mft_entry",
            "mft_entry_number": entry_number,
            "sequence_number": entry["sequence_number"],
            "name": entry["name"],
            "path": resolve_path(entry_number),
            "parent_entry_number": entry["parent_entry_number"],
            "is_allocated": entry["is_allocated"],
            "is_directory": entry["is_directory"],
            "creation_time": entry["creation_time"],
            "modification_time": entry["modification_time"],
            "access_time": entry["access_time"],
            "entry_modification_time": entry["entry_modification_time"],
            "file_size": entry["file_size"],
            "has_alternate_data_streams": entry["has_alternate_data_streams"],
        })

    try:
        mft_file.close()
    except Exception:
        pass


# ── Raw FILE-record fallback ────────────────────────────────────────────────
# Layout per the NTFS on-disk format (MFT_RECORD / attribute headers, as
# documented by libfsntfs/linux-ntfs): 1024-byte "FILE" records with an
# update-sequence fixup array; $STANDARD_INFORMATION (0x10) carries the four
# MACB times, $FILE_NAME (0x30) the parent reference and name, $DATA (0x80)
# the size (named $DATA = alternate data stream). Two streaming passes keep
# memory flat on multi-GB $MFTs: pass 1 keeps only directory names/parents
# (all that path building needs), pass 2 re-reads and emits every entry.
import struct as _struct
from datetime import datetime as _dt, timedelta as _td

RAW_RECORD = 1024
ATTR_SI, ATTR_FN, ATTR_DATA, ATTR_END = 0x10, 0x30, 0x80, 0xFFFFFFFF


def _ft(v):
    if not (116444736000000000 <= v <= 139000000000000000):
        return None
    return (_dt(1601, 1, 1) + _td(microseconds=v / 10)).isoformat() + "Z"


def _fixup(rec):
    usa_off, usa_count = _struct.unpack_from("<HH", rec, 4)
    if usa_count < 2 or usa_off + 2 * usa_count > len(rec):
        return None
    usn = rec[usa_off:usa_off + 2]
    buf = bytearray(rec)
    for i in range(1, usa_count):
        end = i * 512 - 2
        if end + 2 > len(buf) or buf[end:end + 2] != usn:
            return None
        buf[end:end + 2] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
    return bytes(buf)


def _parse_record(raw):
    if raw[:4] != b"FILE":
        return None
    rec = _fixup(raw)
    if rec is None:
        return None
    seq, _links, attr_off, flags = _struct.unpack_from("<HHHH", rec, 0x10)
    base_ref = _struct.unpack_from("<Q", rec, 0x20)[0] & 0xFFFFFFFFFFFF
    if base_ref:
        return None  # extension record — its attributes belong to the base entry
    out = {"sequence_number": seq, "is_allocated": bool(flags & 1), "is_directory": bool(flags & 2),
           "name": "", "parent_entry_number": None, "creation_time": None, "modification_time": None,
           "access_time": None, "entry_modification_time": None, "file_size": None, "has_alternate_data_streams": False}
    best_rank = None
    off = attr_off
    while off + 16 <= len(rec):
        atype, alen = _struct.unpack_from("<II", rec, off)
        if atype == ATTR_END or alen < 16 or off + alen > len(rec):
            break
        nonres, name_len = rec[off + 8], rec[off + 9]
        if not nonres:
            clen, coff = _struct.unpack_from("<IH", rec, off + 0x10)
            content = rec[off + coff:off + coff + clen]
            if atype == ATTR_SI and len(content) >= 32:
                c, m, e, a = _struct.unpack_from("<4Q", content, 0)
                out.update(creation_time=_ft(c), modification_time=_ft(m), entry_modification_time=_ft(e), access_time=_ft(a))
            elif atype == ATTR_FN and len(content) >= 66:
                parent = _struct.unpack_from("<Q", content, 0)[0] & 0xFFFFFFFFFFFF
                nlen, ns = content[64], content[65]
                # Prefer the Win32 / Win32&DOS long name over the 8.3 DOS one.
                rank = {1: 0, 3: 0, 0: 1, 2: 2}.get(ns, 3)
                if best_rank is None or rank < best_rank:
                    best_rank = rank
                    out["name"] = content[66:66 + 2 * nlen].decode("utf-16-le", errors="replace")
                    out["parent_entry_number"] = parent
                    if out["file_size"] is None:
                        out["file_size"] = _struct.unpack_from("<Q", content, 48)[0]
            elif atype == ATTR_DATA:
                if name_len:
                    out["has_alternate_data_streams"] = True
                else:
                    out["file_size"] = clen
        elif atype == ATTR_DATA:
            if name_len:
                out["has_alternate_data_streams"] = True
            elif alen >= 0x38:
                out["file_size"] = _struct.unpack_from("<Q", rec, off + 0x30)[0]
        off += alen
    return out


def _records(path, limit=None):
    with open(path, "rb") as fh:
        idx = 0
        while True:
            chunk = fh.read(RAW_RECORD * 4096)
            if not chunk:
                break
            for o in range(0, len(chunk) - RAW_RECORD + 1, RAW_RECORD):
                if limit is not None and idx >= limit:
                    return
                yield idx, chunk[o:o + RAW_RECORD]
                idx += 1


def mft_fragmentation(path):
    """Reads record 0 (the $MFT's own FILE record) and decodes its unnamed
    $DATA run list. Returns (run_count, first_run_records, total_records) or
    None if record 0 can't be decoded. A copy made by reading only the first
    run off the volume (the collector's raw-read path) holds unrelated disk
    clusters after first_run_records — record numbers past that point would
    be wrong, so callers stop there."""
    with open(path, "rb") as fh:
        rec = _fixup(fh.read(RAW_RECORD))
    if rec is None or rec[:4] != b"FILE":
        return None
    off = _struct.unpack_from("<H", rec, 0x14)[0]
    while off + 16 <= len(rec):
        atype, alen = _struct.unpack_from("<II", rec, off)
        if atype == ATTR_END or alen < 16 or off + alen > len(rec):
            return None
        if atype == ATTR_DATA and rec[off + 8] and rec[off + 9] == 0:
            runs_off = _struct.unpack_from("<H", rec, off + 0x20)[0]
            alloc, real = _struct.unpack_from("<QQ", rec, off + 0x28)
            pos, lengths = off + runs_off, []
            while pos < off + alen and rec[pos] != 0:
                hdr = rec[pos]
                lsize, osize = hdr & 0x0F, hdr >> 4
                lengths.append(int.from_bytes(rec[pos + 1:pos + 1 + lsize], "little"))
                pos += 1 + lsize + osize
            total_clusters = sum(lengths)
            if not lengths or not total_clusters:
                return None
            cluster = alloc // total_clusters
            return len(lengths), lengths[0] * cluster // RAW_RECORD, real // RAW_RECORD
        off += alen
    return None


def parse_raw(path, limit=None):
    dirs = {}
    bad = 0
    for i, raw in _records(path, limit):
        try:
            r = _parse_record(raw)
        except Exception:
            r = None
            bad += 1
        if r and r["is_directory"]:
            dirs[i] = (r["name"], r["parent_entry_number"])
    cache = {ROOT_ENTRY_NUMBER: ""}

    def dir_path(n, depth=0):
        if n in cache:
            return cache[n]
        if depth > MAX_PARENT_CHAIN_DEPTH or n not in dirs:
            return None
        name, parent = dirs[n]
        if parent is None or parent == n:
            cache[n] = name or None
            return cache[n]
        pp = dir_path(parent, depth + 1)
        cache[n] = (f"{pp}\\{name}" if pp else name) if pp is not None else (name or None)
        return cache[n]

    for i, raw in _records(path, limit):
        try:
            r = _parse_record(raw)
        except Exception:
            continue
        if not r:
            continue
        parent = r["parent_entry_number"]
        pp = dir_path(parent) if parent is not None and parent != i else None
        full = (f"{pp}\\{r['name']}" if pp else r["name"]) if pp is not None else (r["name"] or None)
        emit({"type": "mft_entry", "mft_entry_number": i, "path": full if i != ROOT_ENTRY_NUMBER else "", **r})
    if bad:
        emit({"type": "error", "message": f"{bad} MFT records could not be parsed and were skipped"})


if __name__ == "__main__":
    main()
