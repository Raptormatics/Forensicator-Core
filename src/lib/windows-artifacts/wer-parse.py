#!/usr/bin/env python3
"""
Parses a single Windows Error Reporting Report.wer file — a plain text
Key=Value-per-line format (no library/parsing dependency fits this exact
shape, same "hand-roll it" precedent as usnjrnl-parse.py). Real Report.wer
files are typically UTF-16LE (Windows' native text-file encoding); this
tries utf-16 first (Python's "utf-16" codec auto-detects a BOM), then
falls back to utf-8/latin-1.

Every Key=Value line is captured verbatim into raw_fields — nothing is
dropped, regardless of whether this script recognizes the key. Separately,
Sig[n].Name/Sig[n].Value, DynamicSig[n].Name/DynamicSig[n].Value, and
UI[n] lines are collected into sig_fields (full detail, any EventType).

When EventType looks like an APPCRASH-style crash (confirmed from
Microsoft's own WER FAQ bucketing-parameter documentation: Sig[0..7] =
Application Name/Version/Timestamp, Module Name/Version/Timestamp,
Exception Code, Exception Offset — in that fixed order), those 8 slots
are additionally surfaced as named fields. Other EventTypes (BEX, CLR
crashes, etc.) use different Sig[] layouts this script doesn't claim to
know — they keep the full generic sig_fields/raw_fields either way, so
nothing is lost, just not specifically labeled.

Invoked as: wer-parse.py <report_wer_path>

Emits one JSON object per line to stdout:
  {"type": "wer_report", "event_type", "event_time", "report_guid",
   "app_name", "app_version", "app_timestamp", "fault_module_name",
   "fault_module_version", "fault_module_timestamp", "exception_code",
   "exception_offset", "sig_fields": [...], "raw_fields": {...}}
  {"type": "error", "message": str}
"""
import sys
from datetime import datetime, timedelta
import json
import re


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


SIG_RE = re.compile(r"^(Sig|DynamicSig)\[(\d+)\]\.(Name|Value)$", re.IGNORECASE)
UI_RE = re.compile(r"^UI\[(\d+)\]$", re.IGNORECASE)

# Microsoft's documented APPCRASH bucketing parameter order (WER FAQ:
# Application Name, Application Version, Application Build Date, Module
# Name, Module Version, Module Build Date, Exception Code, Code Offset).
APPCRASH_SIG_FIELDS = [
    "app_name", "app_version", "app_timestamp",
    "fault_module_name", "fault_module_version", "fault_module_timestamp",
    "exception_code", "exception_offset",
]


def read_text(path):
    with open(path, "rb") as f:
        data = f.read()
    for encoding in ("utf-16", "utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode("latin-1", errors="replace")


def pick(d, keys):
    lower = {k.lower(): v for k, v in d.items()}
    for k in keys:
        v = lower.get(k.lower())
        if v is not None:
            return v
    return None


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: wer-parse.py <report_wer_path>"})
        sys.exit(1)
    wer_path = sys.argv[1]

    try:
        text = read_text(wer_path)
    except Exception as e:
        emit({"type": "error", "message": f"failed to read Report.wer: {e}"})
        sys.exit(1)

    raw_fields = {}
    sig_slots = {}  # (kind, index) -> {"name": ..., "value": ...}
    ui_fields = []

    try:
        for line in text.splitlines():
            line = line.strip().lstrip("﻿")
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if not key:
                continue
            raw_fields[key] = value

            m = SIG_RE.match(key)
            if m:
                kind = "dynamic_sig" if m.group(1).lower() == "dynamicsig" else "sig"
                index = int(m.group(2))
                field = m.group(3).lower()
                slot = sig_slots.setdefault((kind, index), {"name": None, "value": None})
                slot[field] = value
                continue

            m = UI_RE.match(key)
            if m:
                ui_fields.append({"index": int(m.group(1)), "kind": "ui", "name": None, "value": value})

        sig_fields = [
            {"index": idx, "kind": kind, "name": slot["name"], "value": slot["value"] or ""}
            for (kind, idx), slot in sorted(sig_slots.items(), key=lambda kv: (kv[0][0], kv[0][1]))
        ] + ui_fields

        event_type = pick(raw_fields, ["EventType"])
        event_time = pick(raw_fields, ["EventTime", "Response.time"])
        # Report.wer stores EventTime as a raw FILETIME integer (e.g.
        # "134128363916531015" on Windows 11) — `new Date()` on that is an
        # Invalid Date and failed every report's insert. Convert to ISO UTC.
        if event_time and str(event_time).strip().isdigit():
            ft = int(str(event_time).strip())
            event_time = (datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)).isoformat() + "Z" if 116444736000000000 <= ft <= 139000000000000000 else None
        report_guid = pick(raw_fields, ["ReportIdentifier", "IntegratorReportIdentifier", "ReportGuid"])

        app_name = app_version = app_timestamp = None
        fault_module_name = fault_module_version = fault_module_timestamp = None
        exception_code = exception_offset = None

        if event_type and "appcrash" in event_type.lower():
            sig_values = {idx: slot["value"] for (kind, idx), slot in sig_slots.items() if kind == "sig"}
            resolved = {name: sig_values.get(i) for i, name in enumerate(APPCRASH_SIG_FIELDS)}
            app_name = resolved["app_name"]
            app_version = resolved["app_version"]
            app_timestamp = resolved["app_timestamp"]
            fault_module_name = resolved["fault_module_name"]
            fault_module_version = resolved["fault_module_version"]
            fault_module_timestamp = resolved["fault_module_timestamp"]
            exception_code = resolved["exception_code"]
            exception_offset = resolved["exception_offset"]

        emit({
            "type": "wer_report",
            "event_type": event_type,
            "event_time": event_time,
            "report_guid": report_guid,
            "app_name": app_name,
            "app_version": app_version,
            "app_timestamp": app_timestamp,
            "fault_module_name": fault_module_name,
            "fault_module_version": fault_module_version,
            "fault_module_timestamp": fault_module_timestamp,
            "exception_code": exception_code,
            "exception_offset": exception_offset,
            "sig_fields": sig_fields,
            "raw_fields": raw_fields,
        })
    except Exception as e:
        emit({"type": "error", "message": str(e)})


if __name__ == "__main__":
    main()
