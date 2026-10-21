#!/usr/bin/env python3
"""
Parses a single Windows minidump (.dmp) file via the `minidump` package
(https://github.com/skelsec/minidump, MIT licensed, pure Python, zero
dependencies) — installed into the Windows Artifacts venv alongside
regipy/LnkParse3/olefile (see deploy/install-winartifacts-deps.sh), not
the system python, since it's pure Python with no C extension to link.

Confirmed directly against a real `minidump` 0.0.24 install in the
authoring sandbox (no genuine .dmp sample was available to test against,
so the API surface below is confirmed present and correctly shaped, not
confirmed against a real decoded crash — flagged plainly):
MinidumpFile.parse(path) -> object with `.exception` (ExceptionList,
`.exception_records[i].ThreadId` / `.ExceptionRecord.ExceptionCode_raw` /
`.ExceptionRecord.ExceptionAddress`), `.modules` (MinidumpModuleList,
`.modules[i].name/.baseaddress/.size`), `.sysinfo` (MinidumpSystemInfo,
`.ProcessorArchitecture/.MajorVersion/.MinorVersion/.BuildNumber/
.CSDVersion`, plus a `.guess_os()` method setting `.OperatingSystem`),
`.misc_info` (MinidumpMiscInfo, `.ProcessId/.ProcessCreateTime` — a Unix
timestamp per the public MINIDUMP_MISC_INFO struct).

This is real structured triage data (crashing exception/address/thread,
loaded module list, OS/process info) — not a full symbol-aware stack
walk, which this library doesn't attempt either; that's a materially
bigger undertaking (needs PDB symbols) deliberately out of scope here.

Invoked as: wer-dump-parse.py <dmp_path>

Emits one JSON object per line to stdout:
  {"type": "not_installed"}                                   — minidump missing, degrade gracefully
  {"type": "wer_dump", "exception_code", "exception_address", "faulting_thread_id",
   "process_id", "process_create_time", "os_version", "cpu_architecture",
   "module_list": [{"name", "base_address", "size"}], "misc_info": {...}}
  {"type": "error", "message": str}
"""
import sys
import json
from datetime import datetime, timezone


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def enum_name(v):
    if v is None:
        return None
    return getattr(v, "name", str(v))


def emit_kernel_dump(head):
    import struct
    from datetime import datetime, timedelta
    is64 = head[:8] == b"PAGEDU64"
    major, minor = struct.unpack_from("<II", head, 8)
    if is64:
        machine, processors, bugcheck = struct.unpack_from("<III", head, 0x30)
        params = [f"0x{p:X}" for p in struct.unpack_from("<4Q", head, 0x40)]
        dump_type = struct.unpack_from("<I", head, 0xF98)[0]
        ft = struct.unpack_from("<Q", head, 0xFA8)[0]
    else:
        machine, processors, bugcheck = struct.unpack_from("<III", head, 0x20)
        params = [f"0x{p:X}" for p in struct.unpack_from("<4I", head, 0x2C)]
        dump_type = struct.unpack_from("<I", head, 0xF88)[0]
        ft = struct.unpack_from("<Q", head, 0xFC0)[0]
    system_time = (datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)).isoformat() + "Z" if 116444736000000000 <= ft <= 139000000000000000 else None
    emit({
        "type": "wer_dump",
        "exception_code": f"BugCheck 0x{bugcheck:X}",
        "exception_address": None,
        "faulting_thread_id": None,
        "process_id": None,
        "process_create_time": None,
        "os_version": f"Windows build {minor}",
        "cpu_architecture": {0x8664: "AMD64", 0x14C: "x86", 0xAA64: "ARM64"}.get(machine, f"0x{machine:X}"),
        "module_list": [],
        "misc_info": {
            "dump_kind": "kernel", "signature": head[:8].decode("ascii"), "bugcheck_code": f"0x{bugcheck:X}",
            "bugcheck_parameters": params, "processors": processors, "dump_type": dump_type,
            "crash_time": system_time,
            "note": "Kernel memory dump — header fields only; load it in WinDbg (or upload to RAM Analysis if it is a full dump) for stacks and modules",
        },
    })


def main():
    if len(sys.argv) < 2:
        emit({"type": "error", "message": "usage: wer-dump-parse.py <dmp_path>"})
        sys.exit(1)
    dump_path = sys.argv[1]

    # Kernel memory dumps (WER Kernel_* reports, LiveKernelEvent/BugCheck)
    # are "PAGEDU64"/"PAGEDUMP" crash dumps, not user-mode MDMP minidumps —
    # the minidump library rejects them ("EGAP"). Their DUMP_HEADER is fixed
    # and documented: report the bugcheck instead of failing the file.
    with open(dump_path, "rb") as fh:
        head = fh.read(0x2000)
    if head[:8] in (b"PAGEDU64", b"PAGEDUMP"):
        emit_kernel_dump(head)
        return

    try:
        from minidump.minidumpfile import MinidumpFile
    except ImportError:
        emit({"type": "not_installed"})
        sys.exit(0)

    try:
        mf = MinidumpFile.parse(dump_path)
    except Exception as e:
        emit({"type": "error", "message": f"failed to parse minidump: {e}"})
        sys.exit(1)

    try:
        exception_code = exception_address = None
        faulting_thread_id = None
        if mf.exception and getattr(mf.exception, "exception_records", None):
            rec = mf.exception.exception_records[0]
            faulting_thread_id = rec.ThreadId
            er = rec.ExceptionRecord
            if er is not None:
                code_raw = getattr(er, "ExceptionCode_raw", None)
                exception_code = f"0x{code_raw:08X}" if isinstance(code_raw, int) else enum_name(getattr(er, "ExceptionCode", None))
                addr = getattr(er, "ExceptionAddress", None)
                exception_address = f"0x{addr:X}" if isinstance(addr, int) else None

        process_id = process_create_time = None
        misc_info = {}
        if mf.misc_info:
            process_id = getattr(mf.misc_info, "ProcessId", None)
            raw_create_time = getattr(mf.misc_info, "ProcessCreateTime", None)
            if isinstance(raw_create_time, (int, float)) and raw_create_time > 0:
                try:
                    process_create_time = datetime.fromtimestamp(raw_create_time, tz=timezone.utc).isoformat()
                except Exception:
                    process_create_time = None
            for field in ("ProcessUserTime", "ProcessKernelTime", "ProcessorMaxMhz", "ProcessorCurrentMhz"):
                val = getattr(mf.misc_info, field, None)
                if val is not None:
                    misc_info[field] = val

        os_version = cpu_architecture = None
        if mf.sysinfo:
            try:
                mf.sysinfo.guess_os()
            except Exception:
                pass
            major = getattr(mf.sysinfo, "MajorVersion", None)
            minor = getattr(mf.sysinfo, "MinorVersion", None)
            build = getattr(mf.sysinfo, "BuildNumber", None)
            friendly = getattr(mf.sysinfo, "OperatingSystem", None)
            csd = getattr(mf.sysinfo, "CSDVersion", None)
            parts = [p for p in [friendly, f"{major}.{minor}.{build}" if major is not None else None, csd] if p]
            os_version = " ".join(str(p) for p in parts) if parts else None
            cpu_architecture = enum_name(getattr(mf.sysinfo, "ProcessorArchitecture", None))

        module_list = []
        if mf.modules and getattr(mf.modules, "modules", None):
            for mod in mf.modules.modules:
                base = getattr(mod, "baseaddress", None)
                module_list.append({
                    "name": str(getattr(mod, "name", "") or ""),
                    "base_address": f"0x{base:X}" if isinstance(base, int) else None,
                    "size": getattr(mod, "size", None) or 0,
                })

        emit({
            "type": "wer_dump",
            "exception_code": exception_code,
            "exception_address": exception_address,
            "faulting_thread_id": faulting_thread_id,
            "process_id": process_id,
            "process_create_time": process_create_time,
            "os_version": os_version,
            "cpu_architecture": cpu_architecture,
            "module_list": module_list,
            "misc_info": misc_info,
        })
    except Exception as e:
        emit({"type": "error", "message": str(e)})


if __name__ == "__main__":
    main()
