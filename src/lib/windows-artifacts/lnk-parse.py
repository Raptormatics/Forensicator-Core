#!/usr/bin/env python3
"""
Parses Windows Shortcut (.lnk) structures via LnkParse3
(https://github.com/Matmaus/LnkParse3), installed into the existing
`.venvs/winartifacts` venv alongside regipy — pure-Python, no C-library
linking concern (unlike pyscca in Phase 2).

Invoked as: lnk-parse.py <file_path> <role>
role is one of:
  lnk            — a single standalone .lnk file, parsed once.
  jumplist_custom — a .customDestinations-ms file: a small header (version,
                    category count), then zero or more categories, each
                    holding zero or more shell-object entries (a 16-byte
                    class GUID + the object's own data) ending in a 4-byte
                    0xbabffbab footer. Confirmed against libyal's dtformats
                    "Jump lists format" documentation
                    (https://github.com/libyal/dtformats) and live-tested
                    against real sample files from plaso's test corpus —
                    not guessed. Only LNK-class entries (GUID
                    01140200-0000-0000-c000-000000000046) are something we
                    know how to skip past; any other class ID aborts the
                    current category (we can't know its size) rather than
                    guessing and corrupting the rest of the parse.

LnkParse3's `.size` (bytes actually consumed) is the documented way to
advance past one embedded LNK and find the next entry — plaso's own LNK
parser uses the same approach, explicitly because the LNK's *declared*
file size field "is not reliable for indicating the size of the shell
object data" (dtformats' own wording).

A category's/container's own declared `num_entries`/`num_categories`
counts are ALSO not fully trustworthy — confirmed via live-testing
against real sample files from plaso's test corpus, where more than one
file's header claimed more entries/categories than the file actually
contains. (An earlier version of this script tried to cross-check
`.size` by scanning ahead for the next LNK class GUID, on the theory
that `.size` was overshooting — that was based on a false premise: the
LNK class GUID used as the *container's* entry-header value
(00021401-0000-0000-c000-000000000046) is the exact same byte sequence
as the LNK format's own internal `LinkCLSID` header field, present near
the start of *every* LNK structure, so the scan always "found" the
current entry's own header instead of a real next entry. `.size` was
actually landing exactly on the true end of the data all along — the
file's declared count was just wrong.) The fix: trust `.size`, and when
consuming it would run at or past the end of the file, treat that as the
last real entry and stop iterating — rather than erroring just because
the declared count promised more than the file holds.

Emits one JSON object per line to stdout:
  {"type": "not_installed"}                             — LnkParse3 missing, degrade gracefully
  {"type": "lnk_entry", ...resolved fields}
  {"type": "error", "message": str}                      — unrecoverable failure for this file
"""
import sys
import json

LNK_CLASS_GUID = bytes([0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46])
FOOTER_SIGNATURE = bytes([0xAB, 0xFB, 0xBF, 0xBA])  # 0xbabffbab, little-endian on disk


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


def resolve_target_path(res):
    """Priority mirrors MS-SHLLINK's own target-resolution precedence:
    LinkInfo (local path or UNC network path) first, then StringData's
    relative_path, then a best-effort shell-item chain name as a last
    resort (e.g. for Control-Panel-only shortcuts that carry neither
    LinkInfo nor StringData — confirmed via a real sample during this
    session's research: a bare .lnk to a Control Panel applet has empty
    `link_info`/`data` and relies entirely on the target item chain).
    """
    link_info = res.get("link_info") or {}
    location = link_info.get("location", "")
    if "Local" in location:
        base = link_info.get("local_base_path") or link_info.get("local_base_path_unicode")
        suffix = link_info.get("common_path_suffix") or link_info.get("common_path_suffix_unicode") or ""
        if base:
            return base + suffix
    elif "Network" in location:
        loc_info = link_info.get("location_info") or {}
        net_name = loc_info.get("net_name") or loc_info.get("net_name_unicode")
        suffix = link_info.get("common_path_suffix") or link_info.get("common_path_suffix_unicode") or ""
        if net_name:
            return net_name + ("\\" + suffix if suffix and not suffix.startswith("\\") else suffix)

    data = res.get("data") or {}
    if data.get("relative_path"):
        return data["relative_path"]

    items = (res.get("target") or {}).get("items") or []
    for item in reversed(items):
        if not isinstance(item, dict):
            continue
        name = item.get("primary_name") or item.get("name") or item.get("value")
        if name:
            return str(name)
    return None


def build_entry(lnk, res):
    link_info = res.get("link_info") or {}
    loc_info = link_info.get("location_info") or {}
    data = res.get("data") or {}
    extra = res.get("extra") or {}
    tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK") or {}
    header = res.get("header") or {}

    return {
        "type": "lnk_entry",
        "target_path": resolve_target_path(res),
        "arguments": data.get("command_line_arguments"),
        "working_directory": data.get("working_directory"),
        "icon_location": data.get("icon_location"),
        "creation_time": _iso(header.get("creation_time")),
        "access_time": _iso(header.get("accessed_time")),
        "modification_time": _iso(header.get("modified_time")),
        "file_size": header.get("file_size"),
        "drive_serial_number": loc_info.get("drive_serial_number"),
        "drive_type": loc_info.get("drive_type"),
        "volume_label": loc_info.get("volume_label"),
        "net_name": loc_info.get("net_name"),
        "device_name": loc_info.get("device_name"),
        "machine_id": tracker.get("machine_identifier"),
    }


def parse_one_lnk(buf):
    """Returns (entry_dict_or_None, bytes_consumed). Never raises — a
    malformed single LNK degrades to None/0 so the caller can decide how
    to proceed (abort for a standalone file, skip-and-continue inside a
    jumplist_custom container)."""
    import LnkParse3

    try:
        lnk = LnkParse3.lnk_file(indata=buf)
        res = lnk.get_json(get_all=True)
        return build_entry(lnk, res), lnk.size
    except Exception as e:
        return {"type": "error", "message": f"LNK parse failed: {e}"}, 0


def run_lnk(file_path):
    with open(file_path, "rb") as f:
        buf = f.read()
    entry, _consumed = parse_one_lnk(buf)
    if entry is None:
        emit({"type": "error", "message": "failed to parse LNK file"})
        return
    emit(entry)


def run_jumplist_custom(file_path):
    import struct

    with open(file_path, "rb") as f:
        data = f.read()

    if len(data) < 12:
        emit({"type": "error", "message": "customDestinations-ms file too short to have a header"})
        return

    try:
        version, num_categories, _unknown = struct.unpack("<III", data[0:12])
    except Exception as e:
        emit({"type": "error", "message": f"failed to read customDestinations-ms header: {e}"})
        return

    offset = 12
    for cat_i in range(num_categories):
        if offset + 4 > len(data):
            emit({"type": "error", "message": f"category {cat_i}: truncated before category type"})
            break
        cat_type = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4

        num_entries = 0
        if cat_type == 0:
            if offset + 2 > len(data):
                break
            name_len = struct.unpack("<H", data[offset:offset + 2])[0]
            offset += 2 + name_len * 2
            if offset + 4 > len(data):
                break
            num_entries = struct.unpack("<I", data[offset:offset + 4])[0]
            offset += 4
        elif cat_type == 1:
            offset += 4  # known-category identifier only, no entries
        elif cat_type == 2:
            if offset + 4 > len(data):
                break
            num_entries = struct.unpack("<I", data[offset:offset + 4])[0]
            offset += 4
        else:
            emit({"type": "error", "message": f"category {cat_i}: unrecognized category type {cat_type}"})
            break

        # `num_entries` is a declared count, not a verified one — a real
        # sample in this session's testing claimed 9 entries while the
        # file only actually held 1 (confirmed: `.size` landed exactly at
        # EOF). Iterate up to the declared count, but stop cleanly the
        # moment there isn't a full 16-byte class GUID left to read,
        # rather than treating that as an error.
        for entry_i in range(num_entries):
            if offset + 16 > len(data):
                break
            cls_id = data[offset:offset + 16]
            offset += 16
            if cls_id != LNK_CLASS_GUID:
                emit({"type": "error", "message": f"category {cat_i} entry {entry_i}: non-LNK shell object (class {cls_id.hex()}), cannot determine its size — stopping this category"})
                break

            entry, consumed = parse_one_lnk(data[offset:])
            if entry:
                emit(entry)  # forwards either a lnk_entry or an error, either way try to continue

            if consumed <= 0:
                break
            offset += consumed
            if offset >= len(data):
                break  # that was the last entry the file actually holds

        if offset + 4 > len(data):
            break
        footer = data[offset:offset + 4]
        offset += 4
        if footer != FOOTER_SIGNATURE:
            emit({"type": "error", "message": f"category {cat_i}: footer signature mismatch (got {footer.hex()})"})
            break


def main():
    if len(sys.argv) < 3:
        emit({"type": "error", "message": "usage: lnk-parse.py <file_path> <role>"})
        sys.exit(1)
    file_path, role = sys.argv[1], sys.argv[2]

    try:
        import LnkParse3  # noqa: F401
    except ImportError:
        emit({"type": "not_installed"})
        sys.exit(0)

    try:
        if role == "lnk":
            run_lnk(file_path)
        elif role == "jumplist_custom":
            run_jumplist_custom(file_path)
        else:
            emit({"type": "error", "message": f"unsupported role for lnk-parse.py: {role}"})
            sys.exit(1)
    except Exception as e:
        emit({"type": "error", "message": f"unrecoverable failure: {e}"})
        sys.exit(1)


if __name__ == "__main__":
    main()
