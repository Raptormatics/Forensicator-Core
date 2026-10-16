#!/usr/bin/env python3
"""
Parses the Windows Search database (Windows.edb/Windows.db) via pyesedb
(https://github.com/libyal/libesedb) — same library, same system-python
dependency, and same confirmed API surface (pyesedb.file(), .open(path),
.get_number_of_tables(), .get_table(i), table.get_name(),
table.get_number_of_records(), table.get_record(i),
record.get_number_of_values(), record.get_column_name(i),
record.get_value_data_as_string/integer/floating_point(i)) that
srum-parse.py already uses and documents — see that script's header
comment for the full provenance note.

Windows Search's real-world schema is notoriously per-install-specific:
older/Server builds use readable column names (System_ItemName,
System_ItemUrl, etc.), but many modern Windows 10/11 installs rename
columns to opaque per-property hashes. There is no reliable way to map
those generically without the install's own property-schema database —
this is deliberately a structural table/row dump (every column, whatever
it's actually named, into `details`) rather than a claimed semantic
decode. Internal bookkeeping tables (anything starting with "MSys", ESE's
own system tables) are skipped — not analyst-facing.

Invoked as: search-parse.py <windows_edb_path>

Emits one JSON object per line to stdout:
  {"type": "not_installed"}                                   — pyesedb missing, degrade gracefully
  {"type": "search_entry", "table_name", "record_index", "details": {...}}
  {"type": "error", "message": str}                             — unrecoverable failure for this file/table/record
"""
import sys
import json


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def get_value(record, index):
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
        raw = record.get_value_data(index)
        if isinstance(raw, bytes):
            return raw.hex()
        return raw
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
        out[name] = get_value(record, i)
    return out


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: search-parse.py <windows_edb_path>"})
        sys.exit(1)
    edb_path = sys.argv[1]

    try:
        import pyesedb
    except ImportError:
        emit({"type": "not_installed"})
        sys.exit(0)

    try:
        esedb_file = pyesedb.file()
        esedb_file.open(edb_path)
    except Exception as e:
        emit({"type": "error", "message": f"failed to open Windows Search database: {e}"})
        sys.exit(1)

    try:
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

            if table_name.startswith("MSys"):
                continue  # ESE's own internal bookkeeping, not analyst-facing

            try:
                record_count = table.get_number_of_records()
            except Exception as e:
                emit({"type": "error", "message": f"failed to read record count for {table_name}: {e}"})
                continue

            for r in range(record_count):
                try:
                    record = table.get_record(r)
                    details = row_as_dict(record)
                except Exception as e:
                    emit({"type": "error", "message": f"failed to read record {r} of {table_name}: {e}"})
                    continue

                emit({
                    "type": "search_entry",
                    "table_name": table_name,
                    "record_index": r,
                    "details": details,
                })
    finally:
        try:
            esedb_file.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
