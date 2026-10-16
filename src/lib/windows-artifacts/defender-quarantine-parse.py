#!/usr/bin/env python3
"""
Decrypts and parses Windows Defender quarantine files. Two independent
modes, invoked as:

  defender-quarantine-parse.py entries <entries_file_path>
  defender-quarantine-parse.py resource <resourcedata_file_path> <decrypted_output_path>

RC4 KEY AND RESOURCEDATA STRUCTURE — HIGH CONFIDENCE, independently
verified in this sandbox against a widely-corroborated, runnable
reference (OALabs' gist `windows_defender_unquarantine.py`, forked from
Cuckoo Sandbox's own `quarantine.py` — the key/algorithm are public and
reused by multiple independent community tools, not a single unverified
source). Confirmed: the whole ResourceData file is one continuous RC4
stream under this key; decrypted output starts with magic bytes
0x0B 0xAD 0x00; header length = 0x28 + a little-endian uint32 at byte
offset 8; the quarantined file's own decrypted bytes follow at that
header-length offset.

ENTRIES (QuarantineEntry metadata) STRUCTURE — reconstructed from Fox-IT's
published research (blog.fox-it.com, Dec 2023), which gives a structural
description rather than byte-exact offsets for everything. This script's
confidence varies by section, documented inline at each step: the
60-byte header's internal field layout is THIS SCRIPT'S OWN
reconstruction (the 8 named fields the post lists sum to exactly 60
bytes, which is a strong but not independently confirmed signal); the
Section-1 entry metadata layout (Id/ScanId/Timestamp/ThreatId/One +
DetectionName, "53 bytes + name length" per the post) is high confidence;
the per-resource DetectionPath length encoding is NOT specified by the
post at all and is this script's own best guess (a 4-byte length prefix,
the common Windows serialization convention) — gated by a bounds-check
that falls back to a raw/unparsed marker rather than emitting fabricated
data if that guess doesn't hold on real data. Every decoded field,
including ones this script doesn't confidently recognize, is captured
generically (nothing silently dropped) — same posture as every other
partially-verified format in this codebase.

Fox-IT's own implementation lives in `dissect.target`, which is AGPL-3.0
— already explicitly ruled out for this project (see windows-artifacts
plan). Everything below is implemented from scratch against the
published facts, not by vendoring or adapting that code.

Emits one JSON object per line to stdout:
  entries mode:
    {"type": "quarantine_entry", "entry_id_hex", "scan_id_hex", "threat_id",
     "detection_name", "timestamp", "resources": [...], "raw_fields": {...}}
  resource mode:
    {"type": "quarantine_payload", "magic_valid", "sha256",
     "decrypted_size_bytes", "file_type_sniff"}
  {"type": "error", "message": str}
"""
import sys
import json
import struct
import hashlib
from datetime import datetime, timedelta

RC4_KEY = bytes([
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
    0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
    0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
    0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
    0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
    0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
    0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
    0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
    0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
    0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
    0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
    0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
    0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
    0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
    0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
    0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
    0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
    0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
    0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
    0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
    0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
    0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
    0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
    0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
    0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
    0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53,
])

# Field type codes within a resource's TLV fields (Fox-IT's post).
TYPE_STRING, TYPE_WSTRING, TYPE_DWORD, TYPE_RESOURCE_DATA, TYPE_BYTES, TYPE_QWORD = 1, 2, 3, 4, 5, 6

# Known field IDs (partial — Fox-IT's post explicitly says "most commonly
# observed", not exhaustive). Anything else still gets captured, just
# without a friendly name, in unknown_fields.
KNOWN_FIELD_IDS = {
    0x0A: "flags",
    0x0C: "physical_path",
    0x0D: "detection_context",
    0x0F: "creation_time",
    0x10: "last_access_time",
    0x11: "last_write_time",
}


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def rc4_ksa(key):
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i % len(key)]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox


def rc4_crypt(sbox, data):
    sbox = sbox[:]
    out = bytearray(len(data))
    i = j = 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        val = sbox[(sbox[i] + sbox[j]) % 256]
        out[k] = val ^ data[k]
    return bytes(out)


def rc4_decrypt_fresh(data):
    """Fresh key-scheduling per call — Fox-IT's "each chunk individually
    RC4-encrypted" means each chunk's keystream starts over at byte 0,
    not a continuation of the previous chunk's stream."""
    return rc4_crypt(rc4_ksa(RC4_KEY), data)


def filetime_to_iso(raw_int):
    if not raw_int or raw_int <= 0:
        return None
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=raw_int / 10)).isoformat() + "Z"
    except Exception:
        return None


def sniff_file_type(data):
    if len(data) >= 2 and data[0:2] == b"MZ":
        return "PE"
    if len(data) >= 4 and data[0:4] == b"%PDF":
        return "PDF"
    if len(data) >= 4 and data[0:4] == b"PK\x03\x04":
        return "ZIP/Office"
    if len(data) >= 4 and data[0:4] in (b"\xd0\xcf\x11\xe0",):
        return "OLE/CompoundDoc"
    try:
        data[:256].decode("utf-8")
        return "text"
    except Exception:
        pass
    return "unknown"


def parse_resource_mode(resource_path, output_path):
    with open(resource_path, "rb") as f:
        raw = f.read()

    decrypted = rc4_decrypt_fresh(raw)
    magic_valid = len(decrypted) >= 12 and decrypted[0] == 0x0B and decrypted[1] == 0xAD and decrypted[2] == 0x00
    if not magic_valid:
        emit({"type": "quarantine_payload", "magic_valid": False, "sha256": None,
              "decrypted_size_bytes": None, "file_type_sniff": None})
        return

    headerlen = 0x28 + struct.unpack_from("<I", decrypted, 8)[0]
    if headerlen < 12 or headerlen > len(decrypted):
        emit({"type": "quarantine_payload", "magic_valid": True, "sha256": None,
              "decrypted_size_bytes": None, "file_type_sniff": None})
        return

    payload = decrypted[headerlen:]
    with open(output_path, "wb") as out:
        out.write(payload)

    emit({
        "type": "quarantine_payload",
        "magic_valid": True,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "decrypted_size_bytes": len(payload),
        "file_type_sniff": sniff_file_type(payload),
    })


def align4(offset):
    return (offset + 3) & 0xFFFFFFFC


def parse_resource_fields(buf, start, end):
    """Walk a resource's TLV fields starting at `start`, per Fox-IT's
    documented algorithm: 4-byte-aligned offset, WORD Size + WORD
    (12-bit Identifier | 4-bit Type), then Size bytes of data, advance by
    4 + Size."""
    known = {}
    unknown = []
    offset = start
    while offset + 4 <= end:
        offset = align4(offset)
        if offset + 4 > end:
            break
        size = struct.unpack_from("<H", buf, offset)[0]
        id_type = struct.unpack_from("<H", buf, offset + 2)[0]
        field_id = id_type & 0x0FFF
        field_type = (id_type >> 12) & 0xF
        data_start = offset + 4
        if data_start + size > end:
            break  # can't trust the rest of this resource's field list
        data = buf[data_start:data_start + size]

        value = None
        try:
            if field_type == TYPE_STRING:
                value = data.decode("utf-8", errors="replace")
            elif field_type == TYPE_WSTRING:
                value = data.decode("utf-16-le", errors="replace").rstrip("\x00")
            elif field_type == TYPE_DWORD and size >= 4:
                value = struct.unpack_from("<I", data, 0)[0]
            elif field_type == TYPE_QWORD and size >= 8:
                value = struct.unpack_from("<Q", data, 0)[0]
            elif field_type == TYPE_BYTES:
                value = data.hex()
            else:
                value = data.hex()
        except Exception:
            value = data.hex()

        name = KNOWN_FIELD_IDS.get(field_id)
        if name:
            known[name] = value
        else:
            unknown.append({"id": field_id, "type": field_type, "value": str(value)})

        offset = data_start + size

    return known, unknown


def parse_resource(buf, start, end):
    """DetectionPath/FieldCount/DetectionType length-encoding is NOT
    specified by Fox-IT's post — this is this script's own best-effort
    guess (a 4-byte UTF-16-character-count prefix, the common Windows
    serialization convention also used by $UsnJrnl/BITS-style formats in
    this codebase). Bounds-checked at every step; falls back to an
    "unparsed" marker instead of fabricating data if the guess doesn't
    hold on real data.
    """
    try:
        if start + 4 > end:
            return None
        path_chars = struct.unpack_from("<I", buf, start)[0]
        path_bytes_len = path_chars * 2
        path_start = start + 4
        if path_chars < 0 or path_start + path_bytes_len + 1 > end:
            return {"detection_path": None, "detection_type": None, "unparsed": True,
                    "creation_time": None, "last_access_time": None, "last_write_time": None,
                    "physical_path": None, "flags": None, "unknown_fields": []}
        detection_path = buf[path_start:path_start + path_bytes_len].decode("utf-16-le", errors="replace")

        field_count_offset = path_start + path_bytes_len
        field_count = buf[field_count_offset]
        type_start = field_count_offset + 1
        # DetectionType is a short ASCII-ish string ("file"/"regkey") —
        # read up to the next 4-byte-aligned TLV field start, length
        # bounded defensively rather than trusted from an unverified
        # length field.
        type_end = min(type_start + 16, end)
        raw_type_region = buf[type_start:type_end]
        null_idx = raw_type_region.find(b"\x00")
        detection_type = raw_type_region[:null_idx if null_idx >= 0 else len(raw_type_region)].decode("ascii", errors="ignore").strip() or None

        fields_start = align4(type_start + (null_idx if null_idx and null_idx > 0 else len(raw_type_region)))
        known, unknown = parse_resource_fields(buf, fields_start, end)

        return {
            "detection_path": detection_path,
            "detection_type": detection_type,
            "creation_time": filetime_to_iso(known.get("creation_time")) if isinstance(known.get("creation_time"), int) else None,
            "last_access_time": filetime_to_iso(known.get("last_access_time")) if isinstance(known.get("last_access_time"), int) else None,
            "last_write_time": filetime_to_iso(known.get("last_write_time")) if isinstance(known.get("last_write_time"), int) else None,
            "physical_path": known.get("physical_path"),
            "flags": known.get("flags") if isinstance(known.get("flags"), int) else None,
            "unknown_fields": unknown,
        }
    except Exception:
        return {"detection_path": None, "detection_type": None, "unparsed": True,
                "creation_time": None, "last_access_time": None, "last_write_time": None,
                "physical_path": None, "flags": None, "unknown_fields": []}


def parse_entries_mode(entries_path):
    with open(entries_path, "rb") as f:
        raw = f.read()

    if len(raw) < 60:
        emit({"type": "error", "message": f"Entries file too small for a header: {len(raw)} bytes"})
        return

    header = rc4_decrypt_fresh(raw[:60])

    # This script's own reconstruction of the 60-byte header — see this
    # script's top-of-file comment on confidence level. Two consecutive
    # uint32 "section size" fields are expected around offset 40; a swap
    # between them is the main plausible failure mode if real data
    # disagrees with this layout.
    section1_size = struct.unpack_from("<I", header, 40)[0]
    section2_size = struct.unpack_from("<I", header, 44)[0]

    total_expected = 60 + section1_size + section2_size
    raw_fields = {
        "header_hex": header.hex(),
        "section1_size": section1_size,
        "section2_size": section2_size,
        "file_size": len(raw),
        "layout_self_consistent": total_expected == len(raw),
    }

    if total_expected != len(raw) or section1_size < 53:
        # Our header-layout guess doesn't reconcile with the actual file
        # size — rather than guess further and risk emitting fabricated
        # section/resource data, stop here with what we DO know (the
        # file decrypts and has a plausible header) and flag it plainly.
        emit({
            "type": "quarantine_entry",
            "entry_id_hex": None, "scan_id_hex": None, "threat_id": None,
            "detection_name": None, "timestamp": None,
            "resources": [],
            "raw_fields": raw_fields,
        })
        return

    section1 = rc4_decrypt_fresh(raw[60:60 + section1_size])
    section2_and_resources = rc4_decrypt_fresh(raw[60 + section1_size:60 + section1_size + section2_size])

    entry_id_hex = section1[0:16].hex()
    scan_id_hex = section1[16:32].hex()
    timestamp_raw = struct.unpack_from("<q", section1, 32)[0]
    threat_id = struct.unpack_from("<Q", section1, 40)[0]
    # section1[48:52] == "One" (expected 1), section1[52:53] unaccounted
    # byte per Fox-IT's "53 bytes + name" size fact — not individually
    # decoded, just skipped, since its purpose isn't documented.
    detection_name = section1[53:].decode("utf-16-le", errors="replace").rstrip("\x00")

    resources = []
    if len(section2_and_resources) >= 4:
        resource_count = struct.unpack_from("<I", section2_and_resources, 0)[0]
        offsets = []
        for i in range(min(resource_count, 1000)):  # sane upper bound — never trust a count blindly
            off_pos = 4 + i * 4
            if off_pos + 4 > len(section2_and_resources):
                break
            offsets.append(struct.unpack_from("<I", section2_and_resources, off_pos)[0])

        for i, off in enumerate(offsets):
            end = offsets[i + 1] if i + 1 < len(offsets) else len(section2_and_resources)
            if off >= end or off >= len(section2_and_resources):
                continue
            parsed = parse_resource(section2_and_resources, off, min(end, len(section2_and_resources)))
            if parsed:
                resources.append(parsed)

    emit({
        "type": "quarantine_entry",
        "entry_id_hex": entry_id_hex,
        "scan_id_hex": scan_id_hex,
        "threat_id": str(threat_id),
        "detection_name": detection_name or None,
        "timestamp": filetime_to_iso(timestamp_raw),
        "resources": resources,
        "raw_fields": raw_fields,
    })


def main():
    if len(sys.argv) < 3:
        emit({"type": "error", "message": "usage: defender-quarantine-parse.py <entries|resource> <path> [output_path]"})
        sys.exit(1)

    mode = sys.argv[1]
    try:
        if mode == "entries":
            parse_entries_mode(sys.argv[2])
        elif mode == "resource":
            if len(sys.argv) < 4:
                emit({"type": "error", "message": "resource mode requires an output path"})
                sys.exit(1)
            parse_resource_mode(sys.argv[2], sys.argv[3])
        else:
            emit({"type": "error", "message": f"unknown mode: {mode}"})
            sys.exit(1)
    except Exception as e:
        emit({"type": "error", "message": str(e)})
        sys.exit(1)


if __name__ == "__main__":
    main()
