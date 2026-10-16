#!/usr/bin/env python3
"""
Parses a single Windows notification platform database
(wpndatabase.db/appdb.dat) via Python's stdlib `sqlite3` — no new
dependency, SQLite is self-describing so column names are introspected
live via PRAGMA table_info() rather than hardcoded, sidestepping the
"can't verify exact field names without a real sample" problem most of
this session's other new parsers have.

Opened read-only (`mode=ro` URI) so a live/locked WAL-mode database
doesn't get mutated by SQLite's own recovery behavior on open.

The well-documented Notification/NotificationHandler tables (per Plaso's
published sqlite_plugins/windows_push_notification.py column list —
Order/Id/ActivityId/Type/Payload/Tag/[Group]/HandlerId on Notification;
Id/CreationTime/ModifiedTime/Type/PrimaryId on NotificationHandler) are
recognized leniently when present (several candidate column-name
spellings tried per field, same pick() pattern registry-parse.py/
srum-parse.py already use for this exact kind of uncertainty) — but ANY
table/row still gets emitted with every column dumped generically into
`details`, never silently skipped just because this script doesn't
recognize the schema. Real-world column names/table presence can differ
across Windows builds — flagged plainly, not assumed universal.

Invoked as: notification-parse.py <wpndatabase_path>

Emits one JSON object per line to stdout:
  {"type": "notification_entry", "arrival_time", "expiry_time", "notif_type",
   "tag", "group_name", "handler_id", "handler_label", "payload", "details": {...}}
  {"type": "error", "message": str}
"""
import sys
import json
import sqlite3
from datetime import datetime, timedelta


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def filetime_to_iso(raw_int):
    if not isinstance(raw_int, (int, float)) or raw_int <= 0:
        return None
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=raw_int / 10)).isoformat() + "Z"
    except Exception:
        return None


def pick(d, keys):
    lower = {k.lower(): v for k, v in d.items()}
    for k in keys:
        v = lower.get(k.lower())
        if v is not None:
            return v
    return None


def table_exists(conn, name):
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=? COLLATE NOCASE", (name,)
    ).fetchone()
    return row is not None


def columns_of(conn, table):
    try:
        return [r[1] for r in conn.execute(f"PRAGMA table_info('{table}')").fetchall()]
    except Exception:
        return []


def rows_as_dicts(conn, table, columns):
    out = []
    try:
        cur = conn.execute(f"SELECT * FROM '{table}'")
    except Exception:
        return out
    for row in cur.fetchall():
        out.append(dict(zip(columns, row)))
    return out


def build_handler_labels(conn):
    """NotificationHandler: Id -> a human-ish label (PrimaryId / Type) — same
    "load the small lookup table into memory first" pattern SRUM's
    SruDbIdMapTable already uses."""
    labels = {}
    if not table_exists(conn, "NotificationHandler"):
        return labels
    cols = columns_of(conn, "NotificationHandler")
    for row in rows_as_dicts(conn, "NotificationHandler", cols):
        handler_id = pick(row, ["Id", "PrimaryId"])
        label = pick(row, ["PrimaryId", "Type", "HandlerType"])
        if handler_id is not None:
            labels[str(handler_id)] = str(label) if label is not None else None
    return labels


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: notification-parse.py <wpndatabase_path>"})
        sys.exit(1)
    db_path = sys.argv[1]

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except Exception as e:
        emit({"type": "error", "message": f"failed to open notification database: {e}"})
        sys.exit(1)

    try:
        handler_labels = build_handler_labels(conn)

        if table_exists(conn, "Notification"):
            cols = columns_of(conn, "Notification")
            for row in rows_as_dicts(conn, "Notification", cols):
                handler_id = pick(row, ["HandlerId", "PrimaryId"])
                arrival_raw = pick(row, ["ArrivalTime", "Order"])
                expiry_raw = pick(row, ["ExpiryTime", "ExpirationTime"])

                recognized_keys = {"HandlerId", "PrimaryId", "ArrivalTime", "Order", "ExpiryTime",
                                    "ExpirationTime", "Type", "Tag", "Group", "Payload", "Id"}
                details = {k: v for k, v in row.items() if k not in recognized_keys}

                emit({
                    "type": "notification_entry",
                    "arrival_time": filetime_to_iso(arrival_raw) if isinstance(arrival_raw, (int, float)) else None,
                    "expiry_time": filetime_to_iso(expiry_raw) if isinstance(expiry_raw, (int, float)) else None,
                    "notif_type": str(pick(row, ["Type"])) if pick(row, ["Type"]) is not None else None,
                    "tag": str(pick(row, ["Tag"])) if pick(row, ["Tag"]) is not None else None,
                    "group_name": str(pick(row, ["Group", "GroupName"])) if pick(row, ["Group", "GroupName"]) is not None else None,
                    "handler_id": str(handler_id) if handler_id is not None else None,
                    "handler_label": handler_labels.get(str(handler_id)) if handler_id is not None else None,
                    "payload": str(pick(row, ["Payload"])) if pick(row, ["Payload"]) is not None else None,
                    "details": details,
                })
        else:
            # Schema doesn't match the documented Notification table at
            # all — dump every other table's rows generically rather than
            # emitting nothing, same "structural fallback" posture as
            # search-parse.py.
            for (table_name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                cols = columns_of(conn, table_name)
                for row in rows_as_dicts(conn, table_name, cols):
                    emit({
                        "type": "notification_entry",
                        "arrival_time": None,
                        "expiry_time": None,
                        "notif_type": None,
                        "tag": None,
                        "group_name": None,
                        "handler_id": None,
                        "handler_label": None,
                        "payload": None,
                        "details": {"_table": table_name, **row},
                    })
    except Exception as e:
        emit({"type": "error", "message": str(e)})
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
