#!/usr/bin/env python3
"""
Parses a single BITS queue file (qmgr0.dat/qmgr1.dat — the legacy format
only; the newer Windows 10+ ESE-based qmgr.db has no documented schema
anywhere this project's research could find, and is deliberately left
unparsed) via the `bits_parser` package
(https://github.com/ANSSI-FR/bits_parser, MIT licensed, pure Python —
uses the `construct` binary-parsing library, also MIT) — installed into
the Windows Artifacts venv alongside regipy/LnkParse3/olefile, used here
as a library (`bits.bits.Bits`), not via its CLI.

Confirmed directly against the real package source in the authoring
sandbox (no genuine qmgr0.dat/qmgr1.dat sample was available to test
against, so the library's own documented field schema is used as-is, not
independently re-verified against real data — flagged plainly, though the
library itself is third-party, real, and tested code, not reimplemented
here): `Bits.load_file(path)` returns a `Bits` object; iterating it
(`for job in bits_obj`) runs BOTH clean parsing (`.parse()`) and carving
(`.carve()`, for partially-recovered/deleted job records — flagged with
`job['carved'] = True`), yielding dicts with job_id/name/desc/cmd/sid/
type/priority/state/ctime/mtime (ctime/mtime are real `datetime` objects
via the library's own `FileTime` adapter) and a nested `files` list (each
with dest_fn/src_fn/tmp_fn/download_size/transfer_size).

Emits one row per (job, file-transfer) pair — if a job has no file
transfers, one row with null file fields is still emitted so the job
itself isn't silently dropped.

Invoked as: bits-parse.py <qmgr_file_path>

Emits one JSON object per line to stdout:
  {"type": "not_installed"}                                   — bits_parser missing, degrade gracefully
  {"type": "bits_job", "job_id", "name", "desc", "cmd", "sid", "job_type",
   "priority", "state", "ctime", "mtime", "dest_fn", "src_fn", "tmp_fn",
   "download_size_bytes", "transfer_size_bytes", "is_carved"}
  {"type": "error", "message": str}
"""
import sys
import json
from datetime import datetime


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def iso(value):
    if isinstance(value, datetime):
        return value.isoformat() + ("Z" if value.tzinfo is None else "")
    return None


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: bits-parse.py <qmgr_file_path>"})
        sys.exit(1)
    qmgr_path = sys.argv[1]

    try:
        from bits.bits import Bits
    except ImportError:
        emit({"type": "not_installed"})
        sys.exit(0)

    try:
        bits_obj = Bits.load_file(qmgr_path)
    except Exception as e:
        emit({"type": "error", "message": f"failed to open BITS queue file: {e}"})
        sys.exit(1)

    try:
        for job in bits_obj:
            is_carved = bool(job.get("carved"))
            files = job.get("files") or []

            common = {
                "type": "bits_job",
                "job_id": str(job.get("job_id")) if job.get("job_id") is not None else None,
                "name": job.get("name"),
                "desc": job.get("desc"),
                "cmd": job.get("cmd"),
                "sid": job.get("sid"),
                "job_type": str(job.get("type")) if job.get("type") is not None else None,
                "priority": str(job.get("priority")) if job.get("priority") is not None else None,
                "state": str(job.get("state")) if job.get("state") is not None else None,
                "ctime": iso(job.get("ctime")),
                "mtime": iso(job.get("mtime")),
                "is_carved": is_carved,
            }

            if not files:
                emit({**common, "dest_fn": None, "src_fn": None, "tmp_fn": None,
                      "download_size_bytes": None, "transfer_size_bytes": None})
                continue

            for f in files:
                emit({
                    **common,
                    "dest_fn": f.get("dest_fn"),
                    "src_fn": f.get("src_fn"),
                    "tmp_fn": f.get("tmp_fn"),
                    "download_size_bytes": f.get("download_size"),
                    "transfer_size_bytes": f.get("transfer_size"),
                })
    except Exception as e:
        emit({"type": "error", "message": str(e)})


if __name__ == "__main__":
    main()
