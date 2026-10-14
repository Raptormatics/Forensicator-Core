#!/usr/bin/env python3
"""
Parses a single Windows Prefetch (.pf) file via pyscca
(https://github.com/libyal/libscca), the Python bindings for libyal's
libscca C library — installed as the python3-libscca system package (see
deploy/provision.sh), not pip-installed into a venv, since it links
against the compiled libscca1 C library.

libscca was chosen over the pure-Python `windowsprefetch` package because
that package decompresses Windows 10/11's LZXPRESS-Huffman-compressed
Prefetch format by calling the real Windows API via ctypes — it cannot
run on this Linux-deployed app at all for the most common OS version.
libscca implements the decompression natively in C, confirmed
cross-platform (same library Plaso/log2timeline uses on Linux forensic
workstations).

Invoked as: prefetch-parse.py <pf_file_path>

Verified against a real libscca 20200717 install (python3-libscca .deb
extracted locally, since the authoring sandbox has no root) and genuine
sample .pf files (plaso's test corpus: CMD.EXE/PING.EXE/TASKHOST.EXE).
Confirmed: pyscca.file(), .open(path), .executable_filename, .run_count,
.get_last_run_time(index) (REQUIRES an index — raises TypeError without
one — returns up to 8 timestamps, most-recent first; unused slots come
back as a real datetime at the FILETIME epoch 1601-01-01, not None, so
they're filtered by year rather than truthiness), .number_of_volumes,
.get_volume_information(index) → object with both `.device_path` and
`.serial_number` (an int — the real "volume serial number", formatted
below as Windows' XXXX-XXXX hex; `.device_path` is a different, less
useful field and is only used as a fallback now),
.get_number_of_file_metrics_entries()/.get_file_metrics_entry(i) →
object with `.filename`. All confirmed correct on real data, not guesses.

Emits one JSON object per line to stdout:
  {"type": "not_installed"}                                   — pyscca missing, degrade gracefully
  {"type": "entry", "executable_name", "run_count", "last_run_times": [iso, ...], "volume_serials": [...], "referenced_files": [...]}
  {"type": "error", "message": str}                             — unrecoverable failure for this file
"""
import sys
import json


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def to_utc_iso(t):
    """pyscca returns naive (tzinfo=None) datetimes for Prefetch run times
    — Windows FILETIME is always UTC by definition, but a naive object's
    .isoformat() omits any offset, which a consumer like JS `new Date(...)`
    then treats as LOCAL time instead of UTC (confirmed via direct testing
    on a non-UTC server — see registry-parse.py's filetime_to_iso() for the
    same fix applied there). Appending "Z" fixes it at the source.
    """
    return t.isoformat() + "Z"


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: prefetch-parse.py <pf_file_path>"})
        sys.exit(1)
    pf_path = sys.argv[1]

    try:
        import pyscca
    except ImportError:
        emit({"type": "not_installed"})
        sys.exit(0)

    try:
        scca_file = pyscca.file()
        scca_file.open(pf_path)
    except Exception as e:
        emit({"type": "error", "message": f"failed to open prefetch file: {e}"})
        sys.exit(1)

    try:
        executable_name = getattr(scca_file, "executable_filename", None)
        if not executable_name:
            emit({"type": "error", "message": "no executable_filename on parsed file — likely a pyscca API mismatch, see this script's header comment"})
            return
        run_count = getattr(scca_file, "run_count", None)

        # Last run time(s) — confirmed via a real libscca install +
        # genuine sample .pf files (plaso's test corpus) that
        # get_last_run_time(index) is a required-index method (TypeError
        # without an index) returning up to 8 timestamps, most-recent
        # first. Unused slots (fewer than 8 real runs recorded) come back
        # as a real datetime object at the FILETIME epoch (1601-01-01),
        # not None — `if not t` does NOT filter these out since a
        # datetime object is always truthy, so unused slots are dropped
        # by an explicit year check instead.
        last_run_times = []
        get_indexed = getattr(scca_file, "get_last_run_time", None)
        if callable(get_indexed):
            for i in range(8):
                try:
                    t = get_indexed(i)
                except TypeError:
                    # Not an indexed method — single-timestamp form.
                    try:
                        t = get_indexed()
                    except Exception:
                        t = None
                    if t and getattr(t, "year", 0) > 1601:
                        last_run_times.append(to_utc_iso(t))
                    break
                except Exception:
                    break
                if not t or getattr(t, "year", 0) <= 1601:
                    continue
                last_run_times.append(to_utc_iso(t))

        # Volume serial numbers — confirmed via a real install: the volume
        # info object exposes both `device_path` (e.g.
        # "\Device\HarddiskVolume2") and `serial_number` (an integer, e.g.
        # 0x686c4249). "Volume serial number" in DFIR usage means the
        # latter, formatted the way `vol`/`fsutil` display it
        # (XXXX-XXXX hex) — device_path is a distinct, less useful field
        # that was wrongly preferred before this was verified against a
        # real sample.
        volume_serials = []
        try:
            n_volumes = getattr(scca_file, "number_of_volumes", 0) or 0
            get_volume = getattr(scca_file, "get_volume_information", None)
            if callable(get_volume):
                for i in range(n_volumes):
                    try:
                        vol = get_volume(i)
                        serial_int = getattr(vol, "serial_number", None)
                        if serial_int is not None:
                            hex8 = f"{serial_int & 0xFFFFFFFF:08X}"
                            volume_serials.append(f"{hex8[:4]}-{hex8[4:]}")
                        else:
                            device_path = getattr(vol, "device_path", None)
                            if device_path:
                                volume_serials.append(str(device_path))
                    except Exception:
                        continue
        except Exception:
            pass

        # Referenced files (loaded DLLs + other accessed files) — libscca
        # calls these "file metrics entries".
        referenced_files = []
        try:
            n_metrics = scca_file.get_number_of_file_metrics_entries()
            for i in range(n_metrics):
                try:
                    metric = scca_file.get_file_metrics_entry(i)
                    fname = getattr(metric, "filename", None)
                    if fname:
                        referenced_files.append(str(fname))
                except Exception:
                    continue
        except Exception:
            pass

        emit({
            "type": "entry",
            "executable_name": str(executable_name),
            "run_count": int(run_count) if run_count is not None else None,
            "last_run_times": last_run_times,
            "volume_serials": volume_serials,
            "referenced_files": referenced_files,
        })
    except Exception as e:
        emit({"type": "error", "message": str(e)})
    finally:
        try:
            scca_file.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
