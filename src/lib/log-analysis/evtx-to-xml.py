#!/usr/bin/env python3
"""
Converts a raw .evtx file into the single-line Event XML stream the Log
Analysis Windows decoders consume (one <Event xmlns=...>...</Event> per
line, the same shape the collector's LogChannels\\*.log export uses).
Uses python-evtx (pure Python, Apache-2.0; installed into the Windows
Artifacts venv by deploy/install-winartifacts-deps.sh). Newlines inside
event data (PowerShell script blocks, multi-line messages) are escaped as
&#10; so one event is always exactly one line.

Invoked as: evtx-to-xml.py <file.evtx> <max events>
Writes XML lines to stdout; a final "#FZ-EVTX-SUMMARY {...}" line reports
counts (and truncation) for the caller.
"""
import json
import re
import sys

try:
    import Evtx.Evtx as evtx
except ImportError:
    print('#FZ-EVTX-SUMMARY {"error": "not_installed"}', flush=True)
    sys.exit(0)

SYSTEMTIME_RE = re.compile(r'SystemTime="(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:\+00:00|Z)?"')

path, cap = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 200000
written = failed = 0
truncated = False
with evtx.Evtx(path) as log:
    for record in log.records():
        if written >= cap:
            truncated = True
            break
        try:
            xml = record.xml()
        except Exception:
            failed += 1
            continue
        # python-evtx pretty-prints: drop the whitespace between tags, then
        # escape newlines that are genuinely inside element text.
        line = re.sub(r">\s+<", "><", xml.strip()).replace("\r", "").replace("\n", "&#10;")
        # python-evtx renders SystemTime as "YYYY-MM-DD HH:MM:SS.ffffff+00:00";
        # Windows' own ToXml() (and the decoders) use ISO "...THH:MM:SS.fffffffZ".
        line = SYSTEMTIME_RE.sub(lambda m: f'SystemTime="{m.group(1)}T{m.group(2)}Z"', line)
        sys.stdout.write(line + "\n")
        written += 1
print("#FZ-EVTX-SUMMARY " + json.dumps({"events": written, "failed": failed, "truncated": truncated}), flush=True)
