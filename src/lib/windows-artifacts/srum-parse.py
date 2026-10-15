#!/usr/bin/env python3
"""
Parses SRUDB.dat (the SRUM/System Resource Usage Monitor ESE database)
via pyesedb (https://github.com/libyal/libesedb), the Python bindings
for libyal's libesedb C library — installed as a system package (see
deploy/install-winartifacts-deps.sh), not pip-installed into the
winartifacts venv, since it links a compiled C library — same split as
pyscca/Prefetch and pyfsntfs/$MFT.

Confirmed directly against a real libesedb-python install in the
authoring sandbox (pip install libesedb-python; no genuine SRUDB.dat
sample was available to test against, so the generic ESE API surface
below is confirmed present and correctly shaped, not confirmed against
real decoded SRUM values — flagged plainly): pyesedb.file(), .open(path),
.tables, table.get_name(), table.columns, table.records,
record.get_column_name(i), record.get_value_data_as_string/integer/
floating_point/boolean(i).

SRUM's own table layout (which GUID-named table is which provider, and
each provider's own column names) is NOT something pyesedb or this
sandbox can confirm — it comes from well-documented, widely-cited DFIR
research (SANS's own SRUM posters, the srum-dump/SrumECmd tools' own
published table-GUID mappings), used here as a reference, not verified
against a live decode. Column-name matching is therefore deliberately
LENIENT (several candidate names tried per field, same pick() pattern
registry-parse.py already uses for exactly this kind of
can't-verify-live-field-names uncertainty) rather than assuming one
exact name and silently dropping a table's data on a mismatch — any
table that doesn't match a known provider's columns (or isn't a known
provider at all) still gets a row per record with every column dumped
generically into `details`, not silently skipped.

SruDbIdMapTable resolves the numeric IDs other tables reference
(AppId/UserId) back to real path/SID strings — its own three columns
(IdType, IdIndex, IdBlob) are themselves well-documented; IdBlob is
UTF-16LE text for path-type entries (IdType 0/3) and a raw binary SID
structure for SID-type entries (IdType 1/2) — SID decoding here follows
the standard, stable Windows SID binary layout (revision byte,
sub-authority count byte, 6-byte big-endian authority, N 4-byte
little-endian sub-authorities), not SRUM-specific.

Invoked as: srum-parse.py <srudb_path> [registry_extensions_json_path]
The optional second argument is a path to a JSON file ({guid: dllName})
written by processor.ts from WindowsArtifactUpload.srumExtensionsMap,
when a software_hive file in the same collection already extracted it —
used only to flag whether a given table's GUID is confirmed present in
this specific system's own SRUM\\Extensions registry key, not as the
source of the provider's friendly name (the registry only has a DLL
path, no human label).

Emits one JSON object per line to stdout:
  {"type": "not_installed"}                                   — pyesedb missing, degrade gracefully
  {"type": "srum_entry", "table_name", "provider_label", "timestamp",
   "app_id", "user_sid", "details": {...}, "registry_confirmed": bool|null}
  {"type": "error", "message": str}                             — unrecoverable failure for this file
"""
import sys
import json
from datetime import datetime, timedelta

# GUID -> friendly label, for the well-documented SRUM extensions (see
# this script's own header comment on provenance). Anything not listed
# here still gets a row — provider_label is just None for those.
KNOWN_PROVIDERS = {
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "Energy Usage",
    "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}": "Energy Usage (Long Term)",
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": "Network Data Usage Monitor",
    "{DD6636C4-8929-4683-974E-22C046A43763}": "Network Connectivity Usage Monitor",
    "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}": "Application Resource Usage",
    "{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}": "Application Timeline (Push Notifications)",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "VFU Provider",
    "SruDbIdMapTable": "ID Map (internal)",
    "SruDbCheckpointTable": "Checkpoint (internal)",
}

NETWORK_USAGE_GUID = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
APP_RESOURCE_USAGE_GUID = "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}"


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def filetime_to_iso(raw_int):
    if not raw_int or raw_int <= 0:
        return None
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=raw_int / 10)).isoformat() + "Z"
    except Exception:
        return None


def decode_sid(blob):
    """Standard Windows SID binary layout — revision(1) + sub_authority_count(1)
    + authority(6, big-endian) + sub_authority_count * 4-byte little-endian
    sub-authorities. Stable, documented Windows structure, not SRUM-specific."""
    try:
        if not blob or len(blob) < 8:
            return None
        revision = blob[0]
        sub_count = blob[1]
        authority = int.from_bytes(blob[2:8], "big")
        if len(blob) < 8 + sub_count * 4:
            return None
        parts = [f"S-{revision}-{authority}"]
        for i in range(sub_count):
            sub = int.from_bytes(blob[8 + i * 4: 12 + i * 4], "little")
            parts.append(str(sub))
        return "-".join(parts)
    except Exception:
        return None


def get_value(record, index, column_type):
    """Best-effort typed read — tries the type-specific accessor first,
    falls back to raw bytes. pyesedb's exact column_type integer values
    weren't independently confirmed in this sandbox (no real sample to
    check against), so this tries string/integer/float in order rather
    than branching on a specific type-code match."""
    for getter in ("get_value_data_as_string", "get_value_data_as_integer", "get_value_data_as_floating_point"):
        fn = getattr(record, getter, None)
        if callable(fn):
            try:
                val = fn(index)
                if val is not None:
                    return val
            except Exception:
                continue
    try:
        return record.get_value_data(index)
    except Exception:
        return None


def row_as_dict(record):
    out = {}
    try:
        n = record.get_number_of_values()
    except Exception:
        return out
    for i in range(n):
        try:
            name = record.get_column_name(i)
        except Exception:
            name = f"col_{i}"
        out[name] = get_value(record, i, None)
    return out


def pick(d, keys):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


def build_id_map(esedb_file):
    """SruDbIdMapTable: IdType, IdIndex, IdBlob — resolves the numeric
    AppId/UserId references other tables carry back to real strings."""
    id_map = {}
    try:
        table = esedb_file.get_table_by_name("SruDbIdMapTable")
    except Exception:
        table = None
    if not table:
        return id_map

    try:
        count = table.get_number_of_records()
    except Exception:
        return id_map

    for i in range(count):
        try:
            record = table.get_record(i)
            row = row_as_dict(record)
            id_type = pick(row, ["IdType", "idtype"])
            id_index = pick(row, ["IdIndex", "idindex"])
            id_blob = pick(row, ["IdBlob", "idblob"])
            if id_index is None:
                continue
            resolved = None
            if isinstance(id_blob, (bytes, bytearray)):
                if id_type in (1, 2):
                    resolved = decode_sid(id_blob)
                if resolved is None:
                    try:
                        resolved = id_blob.decode("utf-16-le", errors="ignore").rstrip("\x00")
                    except Exception:
                        resolved = None
            elif isinstance(id_blob, str):
                resolved = id_blob
            id_map[int(id_index)] = resolved or str(id_blob)
        except Exception:
            continue
    return id_map


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: srum-parse.py <srudb_path> [registry_extensions_json_path]"})
        sys.exit(1)
    srudb_path = sys.argv[1]
    registry_guids = set()
    if len(sys.argv) >= 3:
        try:
            with open(sys.argv[2], "r") as f:
                registry_guids = {k.upper() for k in json.load(f).keys()}
        except Exception:
            registry_guids = set()

    try:
        import pyesedb
    except ImportError:
        emit({"type": "not_installed"})
        sys.exit(0)

    try:
        esedb_file = pyesedb.file()
        esedb_file.open(srudb_path)
    except Exception as e:
        emit({"type": "error", "message": f"failed to open SRUDB.dat: {e}"})
        sys.exit(1)

    try:
        id_map = build_id_map(esedb_file)

        try:
            table_count = esedb_file.get_number_of_tables()
        except Exception as e:
            emit({"type": "error", "message": f"failed to read table count: {e}"})
            return

        for t in range(table_count):
            try:
                table = esedb_file.get_table(t)
                table_name = table.get_name()
            except Exception as e:
                emit({"type": "error", "message": f"failed to read table {t}: {e}"})
                continue

            if table_name in ("SruDbIdMapTable", "SruDbCheckpointTable"):
                continue  # internal bookkeeping, not analyst-facing rows

            provider_label = KNOWN_PROVIDERS.get(table_name)
            registry_confirmed = (table_name.upper() in registry_guids) if registry_guids else None

            try:
                record_count = table.get_number_of_records()
            except Exception as e:
                emit({"type": "error", "message": f"failed to read record count for {table_name}: {e}"})
                continue

            for r in range(record_count):
                try:
                    record = table.get_record(r)
                    row = row_as_dict(record)
                except Exception as e:
                    emit({"type": "error", "message": f"failed to read record {r} of {table_name}: {e}"})
                    continue

                app_id_raw = pick(row, ["AppId", "appid"])
                user_id_raw = pick(row, ["UserId", "userid"])
                app_id = id_map.get(int(app_id_raw)) if isinstance(app_id_raw, (int, float)) else (str(app_id_raw) if app_id_raw is not None else None)
                user_sid = id_map.get(int(user_id_raw)) if isinstance(user_id_raw, (int, float)) else (str(user_id_raw) if user_id_raw is not None else None)

                ts_raw = pick(row, ["TimeStamp", "timestamp"])
                timestamp = filetime_to_iso(ts_raw) if isinstance(ts_raw, (int, float)) else None

                details = {k: v for k, v in row.items() if k not in ("AppId", "UserId", "TimeStamp", "appid", "userid", "timestamp")}

                emit({
                    "type": "srum_entry",
                    "table_name": table_name,
                    "provider_label": provider_label,
                    "timestamp": timestamp,
                    "app_id": app_id,
                    "user_sid": user_sid,
                    "details": details,
                    "registry_confirmed": registry_confirmed,
                })
    finally:
        try:
            esedb_file.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
