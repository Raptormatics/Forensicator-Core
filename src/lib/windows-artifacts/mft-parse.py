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

    try:
        mft_file = pyfsntfs.mft_metadata_file()
        mft_file.open(mft_path)
    except Exception as e:
        emit({"type": "error", "message": f"failed to open $MFT file: {e}"})
        sys.exit(1)

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


if __name__ == "__main__":
    main()
