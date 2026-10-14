#!/usr/bin/env python3
"""
Parses a single Windows registry hive (SYSTEM, SOFTWARE, NTUSER.DAT,
Amcache.hve, or UsrClass.dat) via regipy (https://github.com/mkorman90/regipy,
installed as the `regipy[full]` pip extra so pyfwsi/pyfwps are available
for Shellbags), routed by the `role` argument the caller already
determined at upload time (the same role the file was uploaded under —
see WindowsArtifactFile.role in schema.prisma). Invoked as:
registry-parse.py <hive_path> <role>
role is one of: system_hive | software_hive | ntuser_hive | amcache_hive | usrclass_hive

Two extraction strategies, deliberately split:

1. Shimcache / Amcache / BAM / Shellbags — regipy's built-in plugin system
   (regipy.plugins.utils.run_relevant_plugins) auto-detects applicable
   plugins for the hive and returns {plugin_name: [entry_dict, ...]}.
   Each entry_dict's exact key names depend on the installed regipy
   version's plugin implementation, which could not be verified against a
   live install in the environment this script was authored in — so
   rather than guess at field names here and silently drop data on a
   mismatch, every entry is forwarded VERBATIM as {"type":"plugin_entry",
   "plugin": <name>, "data": {...}} and the TypeScript caller
   (registry-engine.ts) does lenient, best-effort field-name matching
   across several candidate keys. If entries come through with
   unexpectedly empty mapped fields, check this plugin's actual field
   names against the installed regipy version and adjust the candidate
   list in registry-engine.ts — no change needed here.

2. Autoruns (Run/RunOnce/Winlogon/AppInit/Services) and UserAssist — hand
   -rolled against regipy's generic, documented key/value API
   (get_key/iter_subkeys/get_values), not a plugin, since "autoruns" isn't
   one regipy plugin's job — it's a curated list of persistence-relevant
   paths this tool cares about, and the generic traversal API is the part
   of regipy's surface that's actually been confirmed stable across
   versions in research for this feature.

Emits one JSON object per line to stdout:
  {"type": "not_installed"}                                   — regipy missing, degrade gracefully
  {"type": "plugin_entry", "plugin": str, "data": dict}        — raw Shimcache/Amcache/BAM plugin output
  {"type": "autorun", "key_path", "value_name", "value_data", "category"}
  {"type": "userassist", "program_path", "run_count", "last_executed", "focus_count", "focus_time_ms"}
  {"type": "error", "message": str}                             — unrecoverable failure for this hive
"""
import sys
import json
import codecs
import struct
from datetime import datetime, timedelta


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def filetime_to_iso(raw: bytes):
    """Decodes a little-endian 8-byte Windows FILETIME into a UTC ISO 8601
    string. FILETIME is always UTC by definition, but datetime(1601, 1, 1)
    + timedelta(...) produces a naive (tzinfo=None) object, so .isoformat()
    omits any offset — e.g. "2012-04-03T22:06:58.124282" with no "Z". A
    consumer like JS `new Date(...)` on a 'T'-separated string with no
    offset treats it as LOCAL time, not UTC, silently shifting it by
    whatever timezone the Node process runs in (confirmed via direct
    testing: a server running in a non-UTC zone shifts these by several
    hours with no visible error). Appending "Z" here fixes it at the
    source for every consumer, instead of needing to audit every call
    site that turns this string into a Date.
    """
    if not raw or len(raw) < 8:
        return None
    try:
        value = struct.unpack("<Q", raw[:8])[0]
        if value == 0:
            return None
        return (datetime(1601, 1, 1) + timedelta(microseconds=value / 10)).isoformat() + "Z"
    except Exception:
        return None


# ── Shimcache / Amcache / BAM — regipy's plugin system, forwarded verbatim ──

def run_plugins(reg):
    try:
        from regipy.plugins.utils import run_relevant_plugins
    except ImportError:
        emit({"type": "not_installed"})
        return False

    try:
        results = run_relevant_plugins(reg, as_json=True)
    except Exception as e:
        emit({"type": "error", "message": f"plugin run failed: {e}"})
        return True

    for plugin_name, entries in (results or {}).items():
        if not entries:
            continue
        for entry in entries:
            emit({"type": "plugin_entry", "plugin": str(plugin_name), "data": entry})
    return True


# ── Autoruns — curated persistence-relevant paths, hand-walked ─────────────

# (key_path, category) lists of plain value-dump keys, per hive role.
# Services (SYSTEM) and Winlogon/AppInit_DLLs (SOFTWARE) are handled
# separately below since they're single-value or per-subkey reads, not a
# flat value-list dump.
#
# Every path below carries a LEADING BACKSLASH — confirmed required by
# reading regipy's own RegistryHive.get_key() source directly: it splits
# the path on "\\" and drops the FIRST element
# (`key_path.split("\\")[1:]`), which silently discards the real first
# path component on any path that doesn't start with "\\". Without the
# leading slash, every one of these lookups would raise
# RegistryKeyNotFoundException (caught below, so it fails silently —
# Autoruns/UserAssist would just always come back empty with no visible
# error). Confirmed by installing regipy and reading registry.py directly
# while building this feature; not a guess.
AUTORUN_PATHS = {
    "software_hive": [
        (r"\Microsoft\Windows\CurrentVersion\Run", "run"),
        (r"\Microsoft\Windows\CurrentVersion\RunOnce", "runonce"),
        (r"\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "run"),
        (r"\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "runonce"),
    ],
    "ntuser_hive": [
        (r"\Software\Microsoft\Windows\CurrentVersion\Run", "run"),
        (r"\Software\Microsoft\Windows\CurrentVersion\RunOnce", "runonce"),
    ],
}
WINLOGON_KEY = r"\Microsoft\Windows NT\CurrentVersion\Winlogon"
APPINIT_KEY = r"\Microsoft\Windows NT\CurrentVersion\Windows"


def emit_autorun(hive_source, key_path, value_name, value_data, category):
    emit({
        "type": "autorun",
        "hive_source": hive_source,
        "key_path": key_path,
        "value_name": value_name,
        "value_data": str(value_data) if value_data is not None else "",
        "category": category,
    })


def walk_value_list(reg, hive_source, key_path, category):
    try:
        key = reg.get_key(key_path)
    except Exception:
        return
    try:
        for v in key.get_values(as_json=True):
            emit_autorun(hive_source, key_path, getattr(v, "name", None) or v.get("name"),
                         getattr(v, "value", None) if hasattr(v, "value") else v.get("value"), category)
    except Exception as e:
        emit({"type": "error", "message": f"autorun walk failed for {key_path}: {e}"})


def run_autoruns_software(reg):
    for key_path, category in AUTORUN_PATHS["software_hive"]:
        walk_value_list(reg, "software", key_path, category)

    # Winlogon Shell/Userinit — single-value keys, not a full value-list dump.
    try:
        key = reg.get_key(WINLOGON_KEY)
        for v in key.get_values(as_json=True):
            name = getattr(v, "name", None) or v.get("name")
            if name in ("Shell", "Userinit"):
                category = "winlogon_shell" if name == "Shell" else "winlogon_userinit"
                emit_autorun("software", WINLOGON_KEY, name,
                             getattr(v, "value", None) if hasattr(v, "value") else v.get("value"), category)
    except Exception:
        pass

    # AppInit_DLLs — classic DLL-injection persistence vector.
    try:
        key = reg.get_key(APPINIT_KEY)
        for v in key.get_values(as_json=True):
            name = getattr(v, "name", None) or v.get("name")
            if name in ("AppInit_DLLs", "LoadAppInit_DLLs"):
                emit_autorun("software", APPINIT_KEY, name,
                             getattr(v, "value", None) if hasattr(v, "value") else v.get("value"), "appinit_dll")
    except Exception:
        pass


def run_autoruns_ntuser(reg):
    for key_path, category in AUTORUN_PATHS["ntuser_hive"]:
        walk_value_list(reg, "ntuser", key_path, category)


def run_autoruns_system(reg):
    # Services — ImagePath + Start for every service, flagged non-default
    # ImagePath locations by the Core rule engine, not filtered here.
    # Uses regipy's own get_control_sets() rather than a hardcoded
    # "ControlSet001" — a hive's ACTIVE control set isn't always 1, and
    # get_control_sets() checks both ControlSet001 and ControlSet002,
    # returning whichever actually exist (same helper regipy's own
    # shimcache/bam plugins use) — confirmed via registry.py's source.
    try:
        services_paths = reg.get_control_sets("Services")
    except Exception as e:
        emit({"type": "error", "message": f"could not resolve control sets: {e}"})
        return

    for services_path in services_paths:
        try:
            services_key = reg.get_key(services_path)
        except Exception:
            continue
        try:
            for subkey in services_key.iter_subkeys() or []:
                try:
                    values = {getattr(v, "name", None) or v.get("name"):
                              (getattr(v, "value", None) if hasattr(v, "value") else v.get("value"))
                              for v in subkey.get_values(as_json=True)}
                except Exception:
                    continue
                image_path = values.get("ImagePath")
                if image_path:
                    emit_autorun("system", f"{services_path}\\{subkey.name}", "ImagePath", image_path, "service")
        except Exception as e:
            emit({"type": "error", "message": f"service enumeration failed at {services_path}: {e}"})


# ── UserAssist — ROT13-decoded value names, FILETIME blob decode ───────────

USERASSIST_ROOT = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"


def run_userassist(reg):
    try:
        root = reg.get_key(USERASSIST_ROOT)
    except Exception:
        return  # no UserAssist data in this hive — not an error, just absent

    try:
        guid_keys = list(root.iter_subkeys() or [])
    except Exception as e:
        emit({"type": "error", "message": f"UserAssist GUID enumeration failed: {e}"})
        return

    for guid_key in guid_keys:
        try:
            count_key = reg.get_key(f"{USERASSIST_ROOT}\\{guid_key.name}\\Count")
        except Exception:
            continue
        try:
            for v in count_key.get_values(as_json=True):
                raw_name = getattr(v, "name", None) or v.get("name")
                raw_value = getattr(v, "value", None) if hasattr(v, "value") else v.get("value")
                if not raw_name:
                    continue
                program_path = codecs.decode(raw_name, "rot_13")
                # Skip the two synthetic UEME_CTLSESSION bookkeeping entries.
                if program_path.startswith("UEME_CTLSESSION"):
                    continue

                run_count, last_executed, focus_count, focus_time_ms = None, None, None, None
                blob = raw_value if isinstance(raw_value, (bytes, bytearray)) else None
                # Exact-length checks, not >= thresholds — both real formats
                # are fixed-size (72 and 16 bytes respectively); confirmed
                # against regipy's own WIN7_USER_ASSIST/WIN_XP_USER_ASSIST
                # construct.Struct definitions while building this feature.
                if blob and len(blob) == 72:
                    # Vista+ format: u32 session(unused) @0, u32 run_count @4,
                    # u32 focus_count @8, u32 focus_time_ms @12, 44 unknown
                    # bytes @16, FILETIME @60.
                    try:
                        run_count = struct.unpack("<I", blob[4:8])[0]
                        focus_count = struct.unpack("<I", blob[8:12])[0]
                        focus_time_ms = struct.unpack("<I", blob[12:16])[0]
                        last_executed = filetime_to_iso(blob[60:68])
                    except Exception:
                        pass
                elif blob and len(blob) == 16:
                    # XP format: u32 session @0, u32 run_count @4, FILETIME @8.
                    # The stored run_count is 5 higher than the real execution
                    # count on this format (the first 5 "sessions" are internal
                    # bookkeeping, not real runs) — confirmed against regipy's
                    # own `parsed_entry.run_counter - 5`; this is a documented
                    # Windows XP UserAssist quirk, not a guess.
                    try:
                        raw_run_count = struct.unpack("<I", blob[4:8])[0]
                        run_count = max(raw_run_count - 5, 0)
                        last_executed = filetime_to_iso(blob[8:16])
                    except Exception:
                        pass

                emit({
                    "type": "userassist",
                    "program_path": program_path,
                    "run_count": run_count,
                    "last_executed": last_executed,
                    "focus_count": focus_count,
                    "focus_time_ms": focus_time_ms,
                })
        except Exception as e:
            emit({"type": "error", "message": f"UserAssist Count walk failed: {e}"})


def main():
    if len(sys.argv) < 3:
        emit({"type": "error", "message": "usage: registry-parse.py <hive_path> <role>"})
        sys.exit(1)
    hive_path, role = sys.argv[1], sys.argv[2]

    try:
        from regipy.registry import RegistryHive
    except ImportError:
        emit({"type": "not_installed"})
        sys.exit(0)

    # Pass the hive type explicitly rather than relying on regipy's own
    # auto-detection (identify_hive_type(), keyed off the ORIGINAL absolute
    # path embedded in the hive's own REGF header by Windows at write time
    # — e.g. requires an exact "\microsoft\windows\usrclass.dat" suffix for
    # UsrClass.dat). That's fragile: the embedded path depends on how the
    # analyst's collection tool preserved it, and our own on-disk storage
    # filename (a random UUID) never matches these patterns at all. We
    # already know the hive type for certain — it's the upload's own
    # `role` — so pass it straight through instead of gambling on
    # detection succeeding. role strings map 1:1 to regipy's hive_type
    # constants by just dropping the "_hive" suffix (confirmed against
    # regipy/hive_types.py: system/software/security/ntuser/amcache/usrclass).
    hive_type = role[:-5] if role.endswith("_hive") else None
    try:
        reg = RegistryHive(hive_path, hive_type=hive_type)
    except Exception as e:
        emit({"type": "error", "message": f"failed to open hive: {e}"})
        sys.exit(1)

    if role == "system_hive":
        if not run_plugins(reg):
            sys.exit(0)
        run_autoruns_system(reg)
    elif role == "software_hive":
        run_autoruns_software(reg)
    elif role == "security_hive":
        # No hand-rolled extraction — SECURITY mainly holds LSA secrets,
        # which regipy doesn't decrypt (needs the SYSTEM hive's bootkey,
        # out of scope here). run_plugins() still runs whatever regipy
        # plugins declare themselves compatible with this hive type; zero
        # matches is a normal, non-error outcome, same as any other role.
        run_plugins(reg)
    elif role == "ntuser_hive":
        # run_plugins() picks up regipy's ntuser_shellbag_plugin (Shellbags
        # — requires the `regipy[full]` extra for pyfwsi/pyfwps; degrades
        # to just skipping that one plugin's entries if not installed,
        # same graceful-degradation posture as everywhere else) alongside
        # whatever else regipy auto-detects for this hive type. Harmless
        # overlap with the hand-rolled UserAssist/Autoruns below — any
        # plugin_entry types the TS mapper doesn't recognize are just
        # ignored, not an error.
        run_plugins(reg)
        run_userassist(reg)
        run_autoruns_ntuser(reg)
    elif role == "amcache_hive":
        if not run_plugins(reg):
            sys.exit(0)
    elif role == "usrclass_hive":
        # Shellbags live here (regipy's usrclass_shellbag_plugin) — same
        # plugin-forwarding mechanism as every other role, nothing hand-rolled.
        if not run_plugins(reg):
            sys.exit(0)
    else:
        emit({"type": "error", "message": f"unsupported role for registry-parse.py: {role}"})
        sys.exit(1)


if __name__ == "__main__":
    main()
