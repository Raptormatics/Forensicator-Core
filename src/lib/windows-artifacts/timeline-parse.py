#!/usr/bin/env python3
"""
Parses a single Windows Timeline database (ActivitiesCache.db, one per
user profile) via Python's stdlib `sqlite3` — no new dependency, same
"self-describing format, live introspection over hardcoded assumptions"
posture as notification-parse.py.

Query shape and column facts are sourced directly from Plaso's own
`windows_timeline.py` SQLite plugin (Apache-2.0 licensed — used here as a
documented-facts reference, not vendored code, same posture as every
other partially-external-sourced format in this codebase):

- Two row kinds, distinguished by `instr(Payload, 'UserEngaged') > 0`:
  - "user_engaged" rows: joined to Activity_PackageId
    (`Activity.Id = Activity_PackageId.ActivityId WHERE Platform =
    'packageid'`) for PackageName; Payload JSON holds
    `activeDurationSeconds` and `reportingApp`.
  - "generic" rows: Payload JSON holds `appDisplayName` (falling back to
    `displayText`) and `description`; AppId is a JSON array of
    {platform, application} entries (kept verbatim in `details` — Plaso's
    own package_identifier resolution from this field has a documented
    logic bug, not relied on here).
- StartTime is a Unix epoch integer, despite SQLite's schema declaring
  the column DATETIME — Plaso's own parser does no FILETIME conversion
  either; confirmed consistent with that, not independently re-verified
  against a live install (same disclosed-but-reasonable-confidence
  posture as every other registry/ESE/SQLite format this session).

Invoked as: timeline-parse.py <activitiescache_db_path>

Emits one JSON object per line to stdout:
  {"type": "timeline_entry", "start_time", "activity_kind", "app_display_name",
   "description", "package_identifier", "active_duration_seconds",
   "reporting_app", "details": {...}}
  {"type": "error", "message": str}
"""
import sys
import json
import sqlite3
from datetime import datetime, timezone


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def epoch_to_iso(raw):
    if not isinstance(raw, (int, float)) or raw <= 0:
        return None
    try:
        return datetime.fromtimestamp(raw, tz=timezone.utc).isoformat()
    except Exception:
        return None


def parse_payload(payload_raw):
    if payload_raw is None:
        return {}
    try:
        if isinstance(payload_raw, bytes):
            payload_raw = payload_raw.decode("utf-8", errors="replace")
        return json.loads(payload_raw)
    except Exception:
        return {}


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


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: timeline-parse.py <activitiescache_db_path>"})
        sys.exit(1)
    db_path = sys.argv[1]

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except Exception as e:
        emit({"type": "error", "message": f"failed to open Windows Timeline database: {e}"})
        sys.exit(1)

    try:
        if not table_exists(conn, "Activity"):
            # Schema doesn't match the documented Activity table at all —
            # dump every table's rows generically rather than emitting
            # nothing, same structural fallback posture as search-parse.py.
            for (table_name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                cols = columns_of(conn, table_name)
                for row in rows_as_dicts(conn, table_name, cols):
                    emit({
                        "type": "timeline_entry",
                        "start_time": None, "activity_kind": "unknown", "app_display_name": None,
                        "description": None, "package_identifier": None,
                        "active_duration_seconds": None, "reporting_app": None,
                        "details": {"_table": table_name, **row},
                    })
            return

        has_package_table = table_exists(conn, "Activity_PackageId")

        if has_package_table:
            try:
                rows = conn.execute(
                    "SELECT StartTime, Payload, PackageName FROM Activity "
                    "INNER JOIN Activity_PackageId ON Activity.Id = Activity_PackageId.ActivityId "
                    "WHERE instr(Payload, 'UserEngaged') > 0 AND Platform = 'packageid'"
                ).fetchall()
            except Exception as e:
                emit({"type": "error", "message": f"UserEngaged query failed: {e}"})
                rows = []

            for start_time, payload_raw, package_name in rows:
                payload = parse_payload(payload_raw)
                emit({
                    "type": "timeline_entry",
                    "start_time": epoch_to_iso(start_time),
                    "activity_kind": "user_engaged",
                    "app_display_name": None,
                    "description": None,
                    "package_identifier": package_name,
                    "active_duration_seconds": payload.get("activeDurationSeconds"),
                    "reporting_app": payload.get("reportingApp"),
                    "details": payload,
                })

        try:
            generic_rows = conn.execute(
                "SELECT StartTime, Payload, AppId FROM Activity WHERE instr(Payload, 'UserEngaged') = 0"
            ).fetchall()
        except Exception as e:
            emit({"type": "error", "message": f"generic Activity query failed: {e}"})
            generic_rows = []

        for start_time, payload_raw, app_id_raw in generic_rows:
            payload = parse_payload(payload_raw)
            app_id_entries = []
            try:
                if app_id_raw:
                    parsed_app_id = json.loads(app_id_raw) if isinstance(app_id_raw, str) else None
                    if isinstance(parsed_app_id, list):
                        app_id_entries = parsed_app_id
            except Exception:
                app_id_entries = []

            details = dict(payload)
            if app_id_entries:
                details["app_id"] = app_id_entries

            emit({
                "type": "timeline_entry",
                "start_time": epoch_to_iso(start_time),
                "activity_kind": "generic",
                "app_display_name": payload.get("appDisplayName") or payload.get("displayText"),
                "description": payload.get("description"),
                "package_identifier": None,
                "active_duration_seconds": None,
                "reporting_app": None,
                "details": details,
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
