#!/usr/bin/env python3
"""
Parses a single Windows registry hive (SYSTEM, SOFTWARE, NTUSER.DAT,
Amcache.hve, or UsrClass.dat) via regipy (https://github.com/mkorman90/regipy,
installed as the `regipy[full]` pip extra so pyfwsi/pyfwps are available
for Shellbags), routed by the `role` argument the caller already
determined at upload time (the same role the file was uploaded under —
see WindowsArtifactFile.role in schema.prisma). Invoked as:
registry-parse.py <hive_path> <role> [log1_path] [log2_path]
role is one of: system_hive | software_hive | security_hive | sam_hive |
default_hive | ntuser_hive | amcache_hive | usrclass_hive

The optional log1_path/log2_path are the hive's own <HIVE>.LOG1/.LOG2
transaction log files, when the collector gathered them alongside the
hive — regipy.recovery.apply_transaction_logs() (already part of this
project's existing regipy dependency) replays their "dirty page"
transactions into a recovered hive, parsed instead of the original.
Recovery failing for any reason (missing/corrupt/mismatched log) falls
back to parsing the original hive directly and logs a non-fatal
scriptError — never aborts the file's processing.

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
  {"type": "srum_extension", "guid", "dll_name"}                 — software_hive only, see run_srum_extensions()
  {"type": "error", "message": str}                             — unrecoverable failure for this hive
"""
import sys
import os
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

# Plugins whose output is either already extracted by the hand-rolled
# walkers below (services -> run_autoruns_system) or is a large dump with
# no triage value (every SafeBoot driver entry) — skipped so they don't
# flood the generic registry_plugin table. Everything else regipy emits is
# kept, see registry-engine.ts's mapUnmappedPluginEntries().
SKIPPED_PLUGINS = {"services", "safeboot_configuration"}


def _plugin_rows(entries):
    """Normalizes one plugin's output into a list of dict rows. Most regipy
    plugins return a list of dicts, but several (ntuser_persistence,
    software_plugin, winver_plugin, timezone_data, ...) return a dict keyed
    by registry path — iterating that directly would yield bare key strings,
    so each top-level key becomes its own row with the key kept as `key`."""
    if isinstance(entries, list):
        return [e if isinstance(e, dict) else {"value": e} for e in entries]
    if isinstance(entries, dict):
        if all(not isinstance(v, (dict, list)) for v in entries.values()):
            return [entries]
        rows = []
        for k, v in entries.items():
            if isinstance(v, dict):
                rows.append({"key": k, **v})
            elif isinstance(v, list) and v and all(isinstance(x, dict) for x in v) and not all("value_type" in x for x in v):
                rows.extend({"key": k, **x} for x in v)
            else:
                rows.append({"key": k, "value": v})
        return rows
    return [{"value": entries}]


def run_plugins(reg, enrich=None):
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

    results = results or {}
    if enrich:
        try:
            enrich(results)
        except Exception as e:
            emit({"type": "error", "message": f"plugin enrichment failed: {e}"})

    for plugin_name, entries in results.items():
        if not entries or plugin_name in SKIPPED_PLUGINS:
            continue
        for entry in _plugin_rows(entries):
            emit({"type": "plugin_entry", "plugin": str(plugin_name), "data": entry})
    return True


# ── SAM — account names, local group membership ──────────────────────────
#
# regipy's samparse plugin decodes each Users\<RID> F/V record (logon
# counts, flags, last logon/password set) but not the account NAME, which
# lives separately under Users\Names\<name> — the RID is stored as that
# subkey's default value's registry TYPE (regipy surfaces it as the
# value_type string, e.g. '500'), confirmed against a real Windows 11 SAM.

SAM_USERS_NAMES = r"\SAM\Domains\Account\Users\Names"
SAM_BUILTIN_ALIASES = r"\SAM\Domains\Builtin\Aliases"
SAM_ACCOUNT_ALIASES = r"\SAM\Domains\Account\Aliases"


def sam_name_map(reg):
    names = {}
    try:
        key = reg.get_key(SAM_USERS_NAMES)
    except Exception:
        return names
    for sk in key.iter_subkeys() or []:
        try:
            for v in sk.get_values(as_json=False):
                try:
                    names[int(str(v.value_type), 0)] = sk.name
                except ValueError:
                    pass  # a recognized REG_* type name, not a RID
        except Exception:
            continue
    return names


def parse_sid(blob, offset=0):
    """Binary SID -> (string, byte length), or (None, 0) on malformed input."""
    if len(blob) < offset + 8:
        return None, 0
    revision = blob[offset]
    count = blob[offset + 1]
    length = 8 + 4 * count
    if revision != 1 or count > 15 or len(blob) < offset + length:
        return None, 0
    authority = int.from_bytes(blob[offset + 2:offset + 8], "big")
    subs = struct.unpack("<" + "I" * count, blob[offset + 8:offset + length]) if count else ()
    return "S-1-%d%s" % (authority, "".join("-%d" % s for s in subs)), length


def sam_alias_rows(reg, aliases_path, names):
    """Each alias's C value: a 0x34-byte header of (offset, length) pairs
    relative to 0x34 — name at 0x10/0x14, member SIDs at 0x28, member count
    at 0x30 — then the variable data. Confirmed against the Administrators
    alias (00000220) of a real Windows 11 SAM."""
    try:
        key = reg.get_key(aliases_path)
    except Exception:
        return
    for sk in key.iter_subkeys() or []:
        if sk.name.lower() in ("members", "names"):
            continue
        try:
            c = next((v.value for v in sk.get_values(as_json=False) if v.name == "C"), None)
            if not isinstance(c, (bytes, bytearray)) or len(c) < 0x34:
                continue
            name_off, name_len = struct.unpack("<II", c[0x10:0x18])
            members_off = struct.unpack("<I", c[0x28:0x2C])[0]
            member_count = struct.unpack("<I", c[0x30:0x34])[0]
            group_name = c[0x34 + name_off:0x34 + name_off + name_len].decode("utf-16-le", errors="replace")
            pos = 0x34 + members_off
            for _ in range(min(member_count, 1000)):
                sid, length = parse_sid(c, pos)
                if not sid:
                    break
                pos += length
                rid = int(sid.rsplit("-", 1)[1])
                emit({"type": "plugin_entry", "plugin": "forensicator_sam_group_membership", "data": {
                    "group_name": group_name,
                    "group_rid": int(sk.name, 16) if all(ch in "0123456789abcdefABCDEF" for ch in sk.name) else sk.name,
                    "member_sid": sid,
                    "member_name": names.get(rid) if sid.startswith("S-1-5-21-") else None,
                    "timestamp": sk.header and _key_last_write(sk),
                }})
        except Exception as e:
            emit({"type": "error", "message": f"SAM alias {sk.name} parse failed: {e}"})


def _key_last_write(key):
    try:
        raw = key.header.last_modified
        return (datetime(1601, 1, 1) + timedelta(microseconds=raw / 10)).isoformat() + "Z" if raw else None
    except Exception:
        return None


def run_sam(reg):
    names = sam_name_map(reg)

    def enrich(results):
        for row in results.get("samparse") or []:
            if isinstance(row, dict) and row.get("rid") is not None:
                row["username"] = names.get(int(row["rid"]))

    if not run_plugins(reg, enrich):
        sys.exit(0)
    sam_alias_rows(reg, SAM_BUILTIN_ALIASES, names)
    sam_alias_rows(reg, SAM_ACCOUNT_ALIASES, names)


# ── SECURITY — LSA secret names and cached domain logons ──────────────────
#
# Secret VALUES and cached-credential hashes are encrypted (LSA key derived
# from the SYSTEM bootkey) and are deliberately NOT decrypted here — but
# which secrets exist is itself evidence (DefaultPassword = a stored
# autologon password, _SC_<svc> = a service running under a stored
# account password), and each NL$<n> cache record's header is cleartext:
# the cached user's RID and the time of that user's last cached logon.

LSA_SECRET_MEANINGS = {
    "DefaultPassword": "Winlogon autologon password stored in LSA",
    "DPAPI_SYSTEM": "DPAPI machine/user master-key protection secret",
    "NL$KM": "Key protecting cached domain logon (NL$) records",
    "$MACHINE.ACC": "Domain machine-account password",
}


def secret_meaning(name):
    if name in LSA_SECRET_MEANINGS:
        return LSA_SECRET_MEANINGS[name]
    if name.upper().startswith("_SC_"):
        return f"Service '{name[4:]}' configured with a stored account password"
    if name.startswith("RasDialParams") or name.startswith("L$_RasConnectionCredentials") or name.startswith("L$_RasDefaultCredentials"):
        return "Stored dial-up/VPN (RAS) connection credentials"
    if name.startswith("L$"):
        return "Local LSA secret"
    if name.startswith("G$"):
        return "Global LSA secret"
    return None


def run_security(reg):
    run_plugins(reg)

    try:
        secrets = reg.get_key(r"\Policy\Secrets")
        for sk in secrets.iter_subkeys() or []:
            updated = None
            try:
                cupd = reg.get_key(rf"\Policy\Secrets\{sk.name}\CupdTime")
                raw = next((v.value for v in cupd.get_values(as_json=False)), None)
                if isinstance(raw, (bytes, bytearray)):
                    updated = filetime_to_iso(raw)
            except Exception:
                pass
            emit({"type": "plugin_entry", "plugin": "forensicator_lsa_secret", "data": {
                "secret_name": sk.name,
                "meaning": secret_meaning(sk.name),
                "last_updated": updated,
                "timestamp": _key_last_write(sk),
            }})
    except Exception:
        pass  # no Secrets key — not an error

    try:
        cache = reg.get_key(r"\Cache")
        for v in cache.get_values(as_json=False):
            if not v.name.startswith("NL$") or v.name == "NL$Control":
                continue
            blob = v.value if isinstance(v.value, (bytes, bytearray)) else b""
            if len(blob) < 96:
                continue
            user_len, domain_len = struct.unpack("<HH", blob[0:4])
            user_rid, primary_group = struct.unpack("<II", blob[16:24])
            flags = struct.unpack("<I", blob[48:52])[0]
            populated = user_len > 0
            emit({"type": "plugin_entry", "plugin": "forensicator_cached_logon", "data": {
                "slot": v.name,
                "populated": populated,
                "user_rid": user_rid if populated else None,
                "primary_group_rid": primary_group if populated else None,
                "last_cached_logon": filetime_to_iso(blob[32:40]) if populated else None,
                "username_length": user_len // 2,
                "domain_length": domain_len // 2,
                "flags": flags,
            }})
    except Exception:
        pass  # no Cache key — workgroup machines often have none


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


# ── SRUM Extensions — GUID -> DllName, needed to interpret SRUDB.dat ──────

SRUM_EXTENSIONS_KEY = r"\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions"


def run_srum_extensions(reg):
    try:
        key = reg.get_key(SRUM_EXTENSIONS_KEY)
    except Exception:
        return  # not present on this system — not an error, just absent
    try:
        for subkey in key.iter_subkeys() or []:
            guid = subkey.name
            dll_name = None
            try:
                for v in subkey.get_values(as_json=True):
                    name = getattr(v, "name", None) or v.get("name")
                    if name == "DllName":
                        dll_name = getattr(v, "value", None) if hasattr(v, "value") else v.get("value")
                        break
            except Exception:
                pass
            emit({"type": "srum_extension", "guid": guid, "dll_name": str(dll_name) if dll_name is not None else None})
    except Exception as e:
        emit({"type": "error", "message": f"SRUM extensions enumeration failed: {e}"})


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


def recover_hive_with_transaction_logs(hive_path, log1_path, log2_path):
    """Replays <HIVE>.LOG1 (primary) and <HIVE>.LOG2 (secondary) "dirty
    page" transactions — uncommitted writes not yet flushed into the hive
    itself — into a recovered copy, via regipy's own
    regipy.recovery.apply_transaction_logs(). Confirmed directly against
    the installed regipy package: this is a real, complete function
    (raises RegistryRecoveryException on a corrupt/mismatched log rather
    than silently producing a wrong result), already part of this
    project's existing regipy dependency — nothing new to install.

    Returns the recovered hive's path on success, or None on any
    failure (log missing/corrupt/mismatched) — callers fall back to
    parsing the original hive_path, never aborting the run over this.
    """
    if not log1_path:
        return None
    try:
        from regipy.recovery import apply_transaction_logs
    except ImportError:
        return None

    restored_path = hive_path + ".recovered"
    try:
        apply_transaction_logs(
            hive_path,
            primary_log_path=log1_path,
            secondary_log_path=log2_path if log2_path else None,
            restored_hive_path=restored_path,
        )
        return restored_path
    except Exception as e:
        emit({"type": "error", "message": f"transaction log recovery failed, parsing original hive instead: {e}"})
        return None


def main():
    if len(sys.argv) < 3:
        emit({"type": "error", "message": "usage: registry-parse.py <hive_path> <role> [log1_path] [log2_path]"})
        sys.exit(1)
    hive_path, role = sys.argv[1], sys.argv[2]
    log1_path = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
    log2_path = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None

    try:
        from regipy.registry import RegistryHive
    except ImportError:
        emit({"type": "not_installed"})
        sys.exit(0)

    recovered_path = recover_hive_with_transaction_logs(hive_path, log1_path, log2_path)
    if recovered_path:
        hive_path = recovered_path

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
    # default_hive (the .DEFAULT user profile, HKU\.DEFAULT) is
    # structurally an NTUSER-format hive — regipy has no separate "default"
    # hive type, and its ntuser plugins apply as-is.
    hive_type = "ntuser" if role == "default_hive" else (role[:-5] if role.endswith("_hive") else None)
    try:
        reg = RegistryHive(hive_path, hive_type=hive_type)
    except Exception as e:
        emit({"type": "error", "message": f"failed to open hive: {e}"})
        sys.exit(1)

    try:
        _dispatch_role(reg, role)
    finally:
        # Clean up the recovered-hive tempfile regardless of which
        # sys.exit() path above was taken — SystemExit still runs this,
        # same as any other exception passing through a finally block.
        if recovered_path and os.path.exists(recovered_path):
            try:
                os.remove(recovered_path)
            except Exception:
                pass


def _dispatch_role(reg, role):
    if role == "system_hive":
        if not run_plugins(reg):
            sys.exit(0)
        run_autoruns_system(reg)
    elif role == "software_hive":
        # Plugins (installed programs, IFEO, network list, Defender config,
        # execution policy, ...) are the slow part on a real SOFTWARE hive
        # — ~3 minutes on a 130MB Windows 11 hive — see registry-engine.ts's
        # timeout.
        run_plugins(reg)
        run_autoruns_software(reg)
        run_srum_extensions(reg)
    elif role == "security_hive":
        run_security(reg)
    elif role == "sam_hive":
        run_sam(reg)
    elif role == "default_hive":
        run_plugins(reg)
        run_userassist(reg)
        for key_path, category in AUTORUN_PATHS["ntuser_hive"]:
            walk_value_list(reg, "default", key_path, category)
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
