#!/usr/bin/env python3
"""
macOS artifacts from the Live Forensicator macOS collector's -A mode
(<host>/artifacts/MacArtifacts/ — see collector-layout.ts's
classifyMacPath()). Invoked as:

    mac-parse.py <file> <role> <path relative to MacArtifacts> [wal] [shm]

Files/<absolute path> holds raw copies mirrored at their real path, so the
original location is the relative path minus its "Files" prefix. A SQLite
database's -wal/-shm companions arrive as the optional last arguments; the
database is opened as a private copy with them, so rows not yet
checkpointed are read without touching the evidence file.

The formats macOS shares with Linux (sudoers, shell histories, SSH files,
cron, startup files, bodyfile) go through linux-parse.py's parsers, with
record kinds renamed mac_* and macOS command-line traits added.

Every record's `details` starts with `findings` — a comma-separated list of
the suspicious traits found ("" when none) — which the built-in macOS rules
match through the rule subject's summary ("findings=...unsigned_executable...").

Standard library only. Emits `record` rows (forensicator_records.py).
"""
import gzip
import importlib.util
import json
import os
import plistlib
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
from datetime import datetime, timezone

from forensicator_records import emit_error, emit_record, extract_iocs, first, read_text

_spec = importlib.util.spec_from_file_location("linux_parse", os.path.join(os.path.dirname(os.path.abspath(__file__)), "linux-parse.py"))
lp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lp)

ROW_CAP = 250000
MAC_EPOCH = 978307200  # 2001-01-01, Core Data / Cocoa absolute time

TEMP_DIRS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/",
             "/var/folders/", "/private/var/folders/")
SYSTEM_EXE_DIRS = ("/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/",
                   "/Library/Apple/", "/opt/homebrew/Cellar/", "/usr/local/Cellar/")
INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh", "python", "python3", "Python", "perl", "perl5",
                "ruby", "osascript", "php", "node", "tclsh", "expect", "nc", "ncat", "socat"}

# macOS command-line traits, on top of linux-parse.py's COMMAND_TRAITS.
MAC_TRAITS = [
    ("quarantine_removal", re.compile(r"\bxattr\b[^|;&\n]*(-d\s+com\.apple\.quarantine|\s-[a-z]*c[a-z]*\b)", re.I)),
    ("security_disable", re.compile(r"spctl\s+(--master-disable|--global-disable|--disable)|csrutil\s+disable|"
                                    r"socketfilterfw\s+--setglobalstate\s+off|LSQuarantine\s+-bool\s+(no|false)|"
                                    r"\btccutil\s+reset\b|\bpfctl\s+-d\b|fdesetup\s+disable", re.I)),
    ("fake_password_prompt", re.compile(r"display dialog[^\n]*(password|hidden answer)", re.I)),
    ("applescript_exec", re.compile(r"\bosascript\b[^|;&\n]*\s-e\b|do shell script", re.I)),
    ("keychain_access", re.compile(r"\bsecurity\s+(find-(generic|internet)-password|dump-keychain|export)\b|\b(chainbreaker|keychaindump)\b", re.I)),
    ("account_creation", re.compile(r"dscl\s+\S+\s+-(create|append)\s+/(Users|Groups/admin)\b|sysadminctl\s+-addUser|dseditgroup\s+.*-a\s+\S+.*\badmin\b", re.I)),
    ("persistence_change", re.compile(r"launchctl\s+(load|bootstrap|enable|submit)\b|defaults\s+write\s+\S*com\.apple\.loginwindow\s+(LoginHook|LogoutHook)|"
                                      r">>?\s*\S*(LaunchAgents|LaunchDaemons|\.zshrc|\.zshenv|\.zprofile|/etc/periodic|emond\.d)", re.I)),
    ("mentions_temp_path", re.compile(r"(^|[\s;&|'\"=])(/private/tmp|/private/var/tmp|/Users/Shared)/\S+", re.I)),
    ("attack_tool", re.compile(r"\b(empyre|poseidon|apfell|evilosx|bifrost|macshellswift)\b", re.I)),
]

lp.KIND_PREFIX = "mac_"
lp.EXTRA_TRAITS = MAC_TRAITS
lp.TEMP_DIRS = TEMP_DIRS
lp.HOME_PREFIXES = ("/Users/", "/var/root/", "/private/var/root/")

traits = lp.traits
details = lp.details


def iso_epoch(value):
    return lp.iso_epoch(value)


def iso_mac(value):
    """Cocoa absolute time (seconds since 2001) -> ISO-8601 UTC."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return iso_epoch(v + MAC_EPOCH) if v > 0 else None


def iso_any(value):
    """datetime, ISO string, Unix or Cocoa seconds -> ISO-8601 UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, (int, float)):
        return iso_epoch(value) if value > 1_000_000_000 else iso_mac(value)
    s = str(value).strip()
    if re.match(r"^\d+(\.\d+)?$", s):
        return iso_any(float(s))
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" +0000", "+00:00"))
        return iso_any(d)
    except ValueError:
        return None


def original_path(rel):
    return lp.original_path(rel)


def norm(path):
    """/private/{etc,var,tmp}/x -> /{etc,var,tmp}/x, for location checks."""
    return re.sub(r"^/private/(etc|var|tmp)/", r"/\1/", path or "")


def owner_from_path(path):
    return lp.owner_from_path(path)


def in_temp(path):
    p = path or ""
    return any(p.startswith(t) for t in TEMP_DIRS) and "/AppTranslocation/" not in p


def load_plist(path):
    with open(path, "rb") as fh:
        return plistlib.load(fh)


def first_value(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def text_of(v, limit=4000):
    if isinstance(v, bytes):
        return f"<{len(v)} bytes>"
    if isinstance(v, (dict, list)):
        try:
            return json.dumps(v, default=str)[:limit]
        except (TypeError, ValueError):
            return str(v)[:limit]
    return str(v)[:limit]


def open_db(db, wal=None, shm=None):
    """A private copy (with its -wal/-shm) so uncheckpointed rows are read
    and the evidence file is never opened read-write."""
    tmpdir = tempfile.mkdtemp(prefix="fz-mac-")
    base = os.path.join(tmpdir, "db.sqlite")
    shutil.copyfile(db, base)
    if wal and os.path.exists(wal):
        shutil.copyfile(wal, base + "-wal")
        if shm and os.path.exists(shm):
            shutil.copyfile(shm, base + "-shm")
    con = sqlite3.connect(base)
    con.row_factory = sqlite3.Row
    return con, tmpdir


def columns(con, table):
    return [r[1] for r in con.execute(f"PRAGMA table_info('{table}')")]


# ── Accounts (Directory Services records) ─────────────────────────────────
def parse_accounts(path, rel, *_):
    orig = original_path(rel)
    rec = load_plist(path)
    name = first_value(rec.get("name")) or os.path.basename(orig)[:-6]
    if "/groups/" in norm(orig):
        members = [m for m in rec.get("users", []) if m]
        found = ["admin_group_member"] if name == "admin" and [m for m in members if m != "root"] else []
        emit_record("mac_group", f"{name}: {', '.join(members) or '(no members)'}", path=orig,
                    details=details(found, group=name, gid=first_value(rec.get("gid")), members=",".join(members),
                                    nested_groups=len(rec.get("nestedgroups", []) or [])))
        return
    uid = str(first_value(rec.get("uid")) or "")
    shell = first_value(rec.get("shell")) or ""
    home = first_value(rec.get("home")) or ""
    hidden = str(first_value(rec.get("IsHidden")) or "").lower() in ("1", "yes", "true")
    policy = {}
    raw = first_value(rec.get("accountPolicyData"))
    if isinstance(raw, bytes):
        try:
            policy = plistlib.loads(raw)
        except Exception:
            policy = {}
    hash_types = []
    shadow = first_value(rec.get("ShadowHashData"))
    if isinstance(shadow, bytes):
        try:
            hash_types = sorted(plistlib.loads(shadow).keys())  # algorithm names only, never the hash
        except Exception:
            pass
    auth = " ".join(str(a) for a in rec.get("authentication_authority", []) or [])
    found = []
    if uid == "0" and name != "root":
        found.append("uid0_non_root")
    if hidden and uid.isdigit() and int(uid) >= 500:
        found.append("hidden_user")
    if uid.isdigit() and 0 < int(uid) < 500 and shell and not re.search(r"(false|nologin)$", shell) and not name.startswith("_"):
        found.append("system_account_with_shell")
    created = iso_any(policy.get("creationTime"))
    emit_record("mac_account", f"{name} (uid {uid})", timestamp=created, path=home or orig, user=name,
                details=details(found, uid=uid, gid=first_value(rec.get("gid")), real_name=first_value(rec.get("realname")),
                                home=home, shell=shell, hidden=hidden, generated_uid=first_value(rec.get("generateduid")),
                                created=created, password_last_set=iso_any(policy.get("passwordLastSetTime")),
                                failed_logins=policy.get("failedLoginCount"), last_failed_login=iso_any(policy.get("failedLoginTimestamp")),
                                password_hash_types=",".join(hash_types), secure_token="SecureToken" in auth,
                                record=orig))


# ── Launch items ─────────────────────────────────────────────────────────
def parse_launch_item(path, rel, *_):
    orig = original_path(rel)
    owner = owner_from_path(orig)
    try:
        rec = load_plist(path)
    except Exception as e:
        emit_error(f"{orig}: not a readable property list ({e})")
        return
    if not isinstance(rec, dict):
        return
    label = str(rec.get("Label") or "")
    args = [str(a) for a in rec.get("ProgramArguments") or [] if a is not None]
    program = str(rec.get("Program") or (args[0] if args else ""))
    cmd = " ".join(args) if args else program
    env = rec.get("EnvironmentVariables") or {}
    found = traits(cmd)
    if in_temp(program):
        found.append("program_in_temp")
    base = os.path.basename(program)
    if base in INTERPRETERS or re.search(r"\.(sh|command|py|pl|rb|js|scpt|php)$", program, re.I):
        found.append("script_program")
    if os.path.basename(orig).startswith(".") or "/." in program:
        found.append("hidden_launch_item")
    if any(k.startswith("DYLD_") for k in env):
        found.append("dyld_injection")
    if label.startswith("com.apple.") and not norm(orig).startswith("/System/"):
        found.append("apple_name_masquerade")
    if owner:
        found.append("user_launch_agent")
    run_at_load = bool(rec.get("RunAtLoad"))
    keep_alive = rec.get("KeepAlive")
    iocs = extract_iocs(cmd)
    emit_record("mac_launch_item", f"{label or os.path.basename(orig)}: {cmd}"[:300], timestamp=iso_epoch(os.path.getmtime(path)),
                path=orig, user=rec.get("UserName") or owner, process=cmd[:4000] or None,
                url=first(iocs, "urls"), ip=first(iocs, "ips"),
                details=details(found, label=label, program=program, arguments=cmd[:4000], run_at_load=run_at_load,
                                keep_alive=text_of(keep_alive, 300) if keep_alive is not None else None,
                                start_interval=rec.get("StartInterval"),
                                calendar=text_of(rec.get("StartCalendarInterval"), 300) if rec.get("StartCalendarInterval") else None,
                                watch_paths=text_of(rec.get("WatchPaths"), 500) if rec.get("WatchPaths") else None,
                                environment=text_of(env, 1000) if env else None, disabled=rec.get("Disabled"),
                                run_as=rec.get("UserName")))


# ── Other property lists ─────────────────────────────────────────────────
APPLE_EMOND_RULES = {"SampleRules.plist"}


def parse_plist(path, rel, *_):
    orig = original_path(rel)
    n = norm(orig)
    name = os.path.basename(orig)
    owner = owner_from_path(orig)
    try:
        rec = load_plist(path)
    except Exception as e:
        emit_error(f"{orig}: not a readable property list ({e})")
        return

    if name == "InstallHistory.plist" and isinstance(rec, list):
        for item in rec[:ROW_CAP]:
            if not isinstance(item, dict):
                continue
            pkgs = item.get("packageIdentifiers") or []
            emit_record("mac_install", f"{item.get('displayName', '?')} {item.get('displayVersion', '')}".strip(),
                        timestamp=iso_any(item.get("date")), process=item.get("processName"),
                        details=details([], display_name=item.get("displayName"), version=item.get("displayVersion"),
                                        installed_by=item.get("processName"), content_type=item.get("contentType"),
                                        packages=",".join(str(p) for p in pkgs)[:2000]))
        return
    if name == "SystemVersion.plist" and isinstance(rec, dict):
        emit_record("mac_os_version", f"{rec.get('ProductName', 'macOS')} {rec.get('ProductVersion', '')} ({rec.get('ProductBuildVersion', '')})",
                    details=details([], version=rec.get("ProductVersion"), build=rec.get("ProductBuildVersion")))
        return
    if not isinstance(rec, dict):
        rec = {"(value)": rec}

    def flags_for(key, value):
        f = []
        if name == "com.apple.loginwindow.plist":
            if key in ("LoginHook", "LogoutHook") and value:
                f.append("login_hook")
                f += traits(str(value))
            if key == "autoLoginUser" and value:
                f.append("auto_login")
            if key == "GuestEnabled" and value is True:
                f.append("guest_enabled")
        if name == "com.apple.alf.plist":
            if key == "globalstate" and value == 0:
                f.append("firewall_off")
        if n.startswith("/etc/emond.d/rules/") and name not in APPLE_EMOND_RULES:
            f.append("emond_rule")
        if n.startswith("/Library/StartupItems/"):
            f.append("startup_item")
        return f

    for i, (key, value) in enumerate(list(rec.items())[:500]):
        found = flags_for(key, value)
        text = text_of(value)
        iocs = extract_iocs(text)
        emit_record("mac_plist_entry", f"{name}: {key} = {text}"[:300], path=orig, user=owner,
                    url=first(iocs, "urls"), ip=first(iocs, "ips"),
                    details=details(found, file=orig, key=key, value=text))


# ── Config / text files ──────────────────────────────────────────────────
# Apple's own periodic scripts; anything else there runs as root on a schedule.
APPLE_PERIODIC = {"110.clean-tmps", "130.clean-msgs", "140.clean-rwho", "199.rotate-fax", "310.accounting",
                  "400.status-disks", "420.status-network", "430.status-rwho", "999.local", "320.whatis", "200.accounting"}


def config_flags(orig, line):
    n = norm(orig)
    f = []
    if n.startswith("/Library/StartupItems/"):
        f.append("startup_item")
    if n in ("/etc/rc.local", "/etc/launchd.conf", "/etc/daily.local", "/etc/weekly.local", "/etc/monthly.local"):
        f.append("boot_or_periodic_script")
    if re.match(r"^/etc/periodic/[^/]+/[^/]+$", n) and os.path.basename(n) not in APPLE_PERIODIC:
        f.append("boot_or_periodic_script")
    if n.endswith("/.ssh/rc") or n == "/etc/ssh/sshrc":
        f.append("ssh_rc")
    return f


lp.EXTRA_CONFIG_FLAGS = config_flags


# ── Command output (Commands/*) ──────────────────────────────────────────
LSOF_RE = re.compile(r"^(\S+)\s+(\d+)\s+(\S+)\s+\S+\s+(IPv4|IPv6)\s+\S+\s+\S+\s+(TCP|UDP)\s+(.*?)(?:\s+\((\w+)\))?\s*$")
# Command names as lsof truncates them (9 characters).
APPLE_LISTENERS = ("launchd", "ControlCe", "rapportd", "sharingd", "remoted", "mDNSRespo", "cupsd", "screensha",
                   "ARDAgent", "smbd", "netbiosd", "kdc", "AirPlayXP", "identitys", "UserEvent", "apsd", "configd",
                   "com.apple", "WiFiAgent", "Spotlight", "ScreensharingAgent")


def hostport(v):
    m = re.match(r"^\[?(.*?)\]?:(\*|\d+)$", v)
    return (m.group(1), m.group(2)) if m else (v, None)


def parse_sockets(lines):
    for line in lines[1:ROW_CAP]:
        m = LSOF_RE.match(line.strip())
        if not m:
            continue
        cmd, pid, user, fam, proto, name, state = m.groups()
        local, _, peer = name.partition("->")
        lh, lp_ = hostport(local)
        ph, pp = hostport(peer) if peer else ("", None)
        found = []
        if state == "LISTEN" and lh not in ("127.0.0.1", "::1", "localhost") and not lh.startswith("127.") \
                and not cmd.startswith(APPLE_LISTENERS):
            found.append("network_listener")
        if cmd.rstrip("0123456789.") in INTERPRETERS:
            found.append("shell_or_interpreter_socket")
        remote = ph if ph and ph not in ("*", "0.0.0.0", "::") else None
        emit_record("mac_socket", f"{proto} {state or ''} {name} ({cmd})".replace("  ", " "), process=cmd, user=user, ip=remote,
                    details=details(found, protocol=proto, state=state, local=local, local_port=lp_, remote=peer or None,
                                    remote_port=pp, pid=pid, family=fam))


def parse_btm(lines):
    """sfltool dumpbtm: one block of 'Key: value' lines per item."""
    items, cur, uid = [], None, None
    for line in lines:
        m = re.match(r"^\s*Records for UID (-?\d+)", line)
        if m:
            uid = m.group(1)
            continue
        if re.match(r"^\s*#\d+:\s*$", line) and not line.startswith(" " * 9):
            cur = {"_uid": uid}
            items.append(cur)
            continue
        m = re.match(r"^\s{4,}([A-Za-z][A-Za-z ]+?):\s(.*)$", line)
        if m and cur is not None:
            cur.setdefault(m.group(1).strip(), m.group(2).strip())
    for it in items[:ROW_CAP]:
        disposition = it.get("Disposition", "")
        exe = it.get("Executable Path", "") or re.sub(r"^file://", "", it.get("URL", ""))
        team = it.get("Team Identifier", "")
        typ = it.get("Type", "")
        enabled = "enabled" in disposition and "disabled" not in disposition
        found = []
        if enabled and not team and not exe.startswith(("/System/", "/usr/")) and not it.get("Identifier", "").startswith("com.apple."):
            found.append("unsigned_background_item")
        if in_temp(exe):
            found.append("item_in_temp")
        found += traits(exe)
        emit_record("mac_background_item", f"{it.get('Name', '?')} ({typ}) {exe}".strip()[:300], path=exe or None,
                    user=it.get("_uid"),
                    details=details(found, name=it.get("Name"), developer=it.get("Developer Name"), team_id=team, type=typ,
                                    disposition=disposition, identifier=it.get("Identifier"), url=it.get("URL"),
                                    executable=it.get("Executable Path"), parent=it.get("Parent Identifier"),
                                    bundle_id=it.get("Bundle Identifier"), uid=it.get("_uid")))


def parse_codesign(lines):
    header = lines[0].split("\t") if lines else []
    for line in lines[1:ROW_CAP]:
        f = line.split("\t")
        if len(f) < len(header):
            f += [""] * (len(header) - len(f))
        row = dict(zip(header, f))
        p, status = row.get("path", ""), row.get("sign_status", "")
        found = []
        if status == "unsigned":
            found.append("unsigned")
        elif status == "adhoc":
            found.append("adhoc_signed")
        elif status == "missing":
            found.append("program_missing")
        if status in ("unsigned", "adhoc") and not p.startswith(SYSTEM_EXE_DIRS):
            found.append("untrusted_signature")
        if in_temp(p):
            found.append("in_temp")
        ctx = row.get("context", "")
        emit_record("mac_code_signature", f"{status or 'unknown'}: {p}" + (f" ({row.get('team_id')})" if row.get("team_id") else ""),
                    path=p, sha256=row.get("sha256") or None,
                    details=details(found, context=ctx, status=status, team_id=row.get("team_id"), authority=row.get("signing_authority"),
                                    identifier=row.get("identifier"), source=row.get("source")))


SECURITY_FLAGS = [
    ("sip", r"disabled", "sip_disabled"),
    ("ssv", r"disabled", "ssv_disabled"),
    ("gatekeeper", r"disabled", "gatekeeper_disabled"),
    ("filevault", r"FileVault is Off", "filevault_off"),
    ("firewall", r"disabled|State = 0", "firewall_off"),
    ("remote_login", r":\s*On\b", "remote_login_on"),
    ("remote_apple_events", r":\s*On\b", "remote_apple_events_on"),
    ("screen_sharing", r"^on$", "screen_sharing_on"),
    ("remote_management", r"^on$", "remote_management_on"),
    ("file_sharing", r"^on$", "file_sharing_on"),
    ("auto_login_user", r"\S", "auto_login"),
    ("guest_account", r"^(1|true|yes)$", "guest_enabled"),
]


def parse_security_state(lines):
    for line in lines:
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        found = [flag for k, rx, flag in SECURITY_FLAGS if k == key and re.search(rx, value, re.I)]
        emit_record("mac_security_setting", f"{key}: {value or '(not set)'}"[:300], details=details(found, setting=key, value=value))


def parse_applications(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except ValueError as e:
        emit_error(f"applications.json: {e}")
        return
    for app in (data.get("SPApplicationsDataType") or [])[:ROW_CAP]:
        p = app.get("path", "")
        source = app.get("obtained_from", "")
        found = []
        if source == "unknown":
            found.append("unknown_source_app")
        if in_temp(p):
            found.append("in_temp")
        signers = app.get("signed_by") or []
        emit_record("mac_application", f"{app.get('_name', '?')} {app.get('version', '')}".strip(), timestamp=iso_any(app.get("lastModified")),
                    path=p, details=details(found, obtained_from=source, signed_by=" > ".join(signers)[:500],
                                            version=app.get("version"), arch=app.get("arch_kind"), info=app.get("info")))


STANDARD_AUTH_PLUGINS = {"builtin", "loginwindow", "PKINITMechanism", "HomeDirMechanism", "MCXMechanism", "CryptoTokenKit",
                         "PSSOAuthPlugin", "KerberosAgent", "authinternal", "DiskUnlock", "SecureTokenUpdate"}


def parse_authorizationdb(path):
    try:
        with open(path, "rb") as fh:
            rec = plistlib.loads(fh.read().split(b"YES (0)")[0])
    except Exception as e:
        emit_error(f"authorizationdb-login.txt: {e}")
        return
    for i, mech in enumerate(rec.get("mechanisms", []) or []):
        plugin = str(mech).split(":", 1)[0]
        found = [] if plugin in STANDARD_AUTH_PLUGINS else ["non_standard_auth_mechanism"]
        emit_record("mac_auth_mechanism", f"system.login.console: {mech}", details=details(found, mechanism=mech, plugin=plugin, position=i + 1))


def parse_proxy(lines):
    text = "\n".join(lines)
    enabled = [m.group(1) for m in re.finditer(r"\b(\w+?)Enable\s*:\s*1\b", text) if m.group(1) != "ExcludeSimpleHostnames"]
    values = dict(re.findall(r"\b(HTTPProxy|HTTPSProxy|SOCKSProxy|FTPProxy|ProxyAutoConfigURLString)\s*:\s*(\S+)", text))
    found = ["proxy_configured"] if enabled else []
    iocs = extract_iocs(" ".join(values.values()))
    emit_record("mac_proxy", "Proxies: " + (", ".join(f"{k}" for k in enabled) or "none"), url=values.get("ProxyAutoConfigURLString"),
                ip=first(iocs, "ips"), details=details(found, enabled=",".join(enabled), **{k.lower(): v for k, v in values.items()}))


def parse_kexts(lines):
    for line in lines[:ROW_CAP]:
        m = re.search(r"\s([A-Za-z0-9-]+(?:\.[A-Za-z0-9_-]+){2,})\s+\(\d", line)
        if not m:
            continue
        bid = m.group(1)
        found = [] if bid.startswith("com.apple.") else ["non_apple_kext"]
        emit_record("mac_kext", bid, details=details(found, bundle_id=bid, line=line.strip()[:500]))


def parse_command_output(path, rel, *_):
    name = os.path.basename(rel)
    stem = name.rsplit(".", 1)[0]
    if name == "applications.json":
        parse_applications(path)
        return
    if name == "authorizationdb-login.txt":
        parse_authorizationdb(path)
        return
    text, _enc = read_text(path)
    lines = text.splitlines()
    handlers = {"sockets": parse_sockets, "btm": parse_btm, "codesign": parse_codesign, "security-state": parse_security_state,
                "proxy": parse_proxy, "kexts": parse_kexts}
    if stem in handlers:
        handlers[stem](lines)
        return
    found_for = {}
    if stem == "system-extensions":
        found_for = {"[activated enabled]": "third_party_system_extension"}
    if stem == "profiles":
        found_for = {"profileIdentifier:": "configuration_profile"}
    kind = "mac_cmd_" + re.sub(r"[^a-z0-9]+", "_", stem.lower()).strip("_")
    for n, line in enumerate(lines[:ROW_CAP], 1):
        if not line.strip():
            continue
        found = [flag for needle, flag in found_for.items() if needle in line]
        iocs = extract_iocs(line)
        emit_record(kind, line.strip()[:300], ip=first(iocs, "ips"), url=first(iocs, "urls"),
                    details=details(found, line=line.rstrip()[:4000], line_number=n, source=rel))


# ── Processes ────────────────────────────────────────────────────────────
def parse_processes(path, rel, *_):
    text, _enc = read_text(path)
    lines = text.splitlines()
    if not lines:
        return
    header = lines[0].split("\t")
    for line in lines[1:ROW_CAP]:
        f = line.split("\t")
        if len(f) < len(header):
            f += [""] * (len(header) - len(f))
        row = dict(zip(header, f))
        exe, cmd, status = row.get("exe", ""), row.get("cmdline", ""), row.get("sign_status", "")
        found = traits(cmd)
        if row.get("exe_deleted") == "1":
            found.append("deleted_executable")
        if in_temp(exe):
            found.append("exe_in_temp")
        if exe and re.search(r"/\.[^/]+$", exe):
            found.append("hidden_executable")
        if status in ("unsigned", "adhoc") and exe and not exe.startswith(SYSTEM_EXE_DIRS):
            found.append("untrusted_signature")
        emit_record("mac_process", f"{row.get('pid')} {row.get('comm', '')} {cmd}"[:300], timestamp=row.get("start_utc") or None,
                    path=exe or None, user=row.get("user") or row.get("uid") or None, process=cmd[:4000] or row.get("comm"),
                    sha256=row.get("exe_sha256") or None,
                    details=details(found, pid=row.get("pid"), ppid=row.get("ppid"), uid=row.get("uid"), comm=row.get("comm"),
                                    cwd=row.get("cwd"), sign_status=status, team_id=row.get("team_id"),
                                    signing_authority=row.get("signing_authority"), exe_deleted=row.get("exe_deleted") == "1"))


# ── SQLite databases ─────────────────────────────────────────────────────
SENSITIVE_TCC = {
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServicePostEvent": "Synthetic input",
    "kTCCServiceAppleEvents": "Automation",
    "kTCCServiceSystemPolicySysAdminFiles": "Administer files",
    "kTCCServiceEndpointSecurityClient": "Endpoint Security",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
}
TCC_REASONS = {1: "error", 2: "user_consent", 3: "user_set", 4: "system_set", 5: "service_policy", 6: "mdm_policy",
               7: "override_policy", 8: "missing_usage_string", 9: "prompt_timeout", 10: "preflight_unknown",
               11: "entitled", 12: "app_type_policy"}


def parse_tcc(path, rel, wal=None, shm=None):
    orig = original_path(rel)
    owner = owner_from_path(orig) or "system"
    con, tmpdir = open_db(path, wal, shm)
    try:
        cols = columns(con, "access")
        for r in con.execute("SELECT * FROM access").fetchmany(ROW_CAP):
            row = dict(zip(cols, r))
            service, client = str(row.get("service", "")), str(row.get("client", ""))
            if "auth_value" in row:
                value = row.get("auth_value")
                granted = value in (2, 3)
            else:
                value = row.get("allowed")
                granted = value == 1
            path_client = row.get("client_type") == 1
            found = []
            if granted and service in SENSITIVE_TCC and not client.startswith(("com.apple.", "/System/", "/usr/libexec/")):
                found.append("sensitive_grant")
                if path_client:
                    found.append("binary_path_client")
            if path_client and in_temp(client):
                found.append("client_in_temp")
            label = SENSITIVE_TCC.get(service, service.replace("kTCCService", ""))
            emit_record("mac_tcc_grant", f"{label}: {client} {'granted' if granted else 'denied'}", timestamp=iso_epoch(row.get("last_modified")),
                        path=client if path_client else None, user=owner,
                        details=details(found, service=service, client=client, client_type="path" if path_client else "bundle_id",
                                        granted=granted, auth_value=value, auth_reason=TCC_REASONS.get(row.get("auth_reason"), row.get("auth_reason")),
                                        target=row.get("indirect_object_identifier"), database=orig))
    finally:
        con.close()
        shutil.rmtree(tmpdir, ignore_errors=True)


def parse_quarantine(path, rel, wal=None, shm=None):
    orig = original_path(rel)
    user = owner_from_path(orig)
    con, tmpdir = open_db(path, wal, shm)
    try:
        for r in con.execute("SELECT * FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp").fetchmany(ROW_CAP):
            row = dict(r)
            url = row.get("LSQuarantineDataURLString") or ""
            origin = row.get("LSQuarantineOriginURLString") or ""
            found = []
            host = re.sub(r"^[a-z]+://([^/:]+).*$", r"\1", url, flags=re.I)
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                found.append("download_from_ip")
            if re.search(r"\.(pkg|dmg|app\.zip|command|sh|scpt|terminal|jar|py)(\?|$)", url, re.I):
                found.append("executable_download")
            agent = row.get("LSQuarantineAgentName") or row.get("LSQuarantineAgentBundleIdentifier") or "?"
            iocs = extract_iocs(url + " " + origin)
            emit_record("mac_quarantine_event", f"{agent}: {url or origin or '(no URL)'}"[:300], timestamp=iso_mac(row.get("LSQuarantineTimeStamp")),
                        user=user, url=url or origin or None, ip=first(iocs, "ips"), process=agent,
                        details=details(found, agent=agent, agent_bundle=row.get("LSQuarantineAgentBundleIdentifier"), origin=origin,
                                        sender=row.get("LSQuarantineSenderName"), sender_address=row.get("LSQuarantineSenderAddress"),
                                        event_id=row.get("LSQuarantineEventIdentifier")))
    finally:
        con.close()
        shutil.rmtree(tmpdir, ignore_errors=True)


KNOWLEDGE_STREAMS = ("/app/usage", "/app/inFocus", "/app/activity", "/app/webUsage", "/safari/history", "/device/isLocked",
                     "/display/isBacklit", "/notification/usage", "/app/intents")


def parse_knowledgec(path, rel, wal=None, shm=None):
    orig = original_path(rel)
    user = owner_from_path(orig) or "system"
    con, tmpdir = open_db(path, wal, shm)
    try:
        has_source = "ZSOURCE" in [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        q = ("SELECT o.ZSTREAMNAME AS stream, o.ZVALUESTRING AS value, o.ZSTARTDATE AS start, o.ZENDDATE AS end"
             + (", s.ZBUNDLEID AS bundle FROM ZOBJECT o LEFT JOIN ZSOURCE s ON o.ZSOURCE = s.Z_PK" if has_source else ", NULL AS bundle FROM ZOBJECT o")
             + f" WHERE o.ZSTREAMNAME IN ({','.join('?' * len(KNOWLEDGE_STREAMS))}) ORDER BY o.ZSTARTDATE")
        for r in con.execute(q, KNOWLEDGE_STREAMS).fetchmany(ROW_CAP):
            start, end = iso_mac(r["start"]), iso_mac(r["end"])
            secs = (r["end"] - r["start"]) if r["start"] and r["end"] else None
            value = r["value"] or r["bundle"] or ""
            emit_record("mac_app_usage", f"{r['stream']} {value}" + (f" ({int(secs)}s)" if secs is not None else ""), timestamp=start,
                        user=user, url=value if str(value).startswith("http") else None,
                        details=details([], stream=r["stream"], value=value, bundle=r["bundle"], start=start, end=end,
                                        seconds=int(secs) if secs is not None else None))
    finally:
        con.close()
        shutil.rmtree(tmpdir, ignore_errors=True)


def parse_xprotect(path, rel, wal=None, shm=None):
    """XProtect's behavioural-detection database (macOS 13+). The schema is
    undocumented: every row of every table is kept, with a timestamp from
    any date/time column."""
    orig = original_path(rel)
    con, tmpdir = open_db(path, wal, shm)
    try:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for t in tables:
            cols = columns(con, t)
            for r in con.execute(f"SELECT * FROM '{t}'").fetchmany(ROW_CAP):
                row = {k: (v if not isinstance(v, bytes) else f"<{len(v)} bytes>") for k, v in zip(cols, r)}
                ts = next((iso_any(row[c]) for c in cols if re.search(r"date|time|^dt$", c, re.I) and row.get(c)), None)
                texts = [str(v) for k, v in row.items() if isinstance(v, str) and v and not re.search(r"date|time|^dt$", k, re.I)]
                p = next((str(v) for k, v in row.items() if isinstance(v, str) and v.startswith("/")), None)
                emit_record("mac_xprotect_event", f"{t}: {' | '.join(texts)[:250]}", timestamp=ts, path=p,
                            details=details(["xprotect_event"], table=t, database=orig, **{k: v for k, v in row.items() if v not in (None, "")}))
    finally:
        con.close()
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── FSEvents ─────────────────────────────────────────────────────────────
FSE_FLAGS = [
    (0x00000001, "FolderEvent"), (0x00000002, "Mount"), (0x00000004, "Unmount"), (0x00000020, "EndOfTransaction"),
    (0x00000800, "LastHardLinkRemoved"), (0x00001000, "HardLink"), (0x00004000, "SymbolicLink"), (0x00008000, "FileEvent"),
    (0x00010000, "PermissionChange"), (0x00020000, "ExtendedAttrModified"), (0x00040000, "ExtendedAttrRemoved"),
    (0x00100000, "DocumentRevisioning"), (0x00400000, "ItemCloned"), (0x01000000, "Created"), (0x02000000, "Removed"),
    (0x04000000, "InodeMetaMod"), (0x08000000, "Renamed"), (0x10000000, "Modified"), (0x20000000, "Exchange"),
    (0x40000000, "FinderInfoMod"), (0x80000000, "FolderCreated"),
]
# FSEvents record every change on the volume; only these paths become
# records (the raw pages stay in the collection for a full parse).
FSE_PERSISTENCE = re.compile(r"/Library/(LaunchAgents|LaunchDaemons|StartupItems|Security/SecurityAgentPlugins|Extensions)/|"
                             r"^/(private/)?etc/(periodic|emond\.d|sudoers|pam\.d|ssh/sshd_config|zshrc|zprofile|zshenv|profile|bashrc)|"
                             r"/\.ssh/|/\.(zshrc|zshenv|zprofile|zlogin|bashrc|bash_profile|profile)$|^/(private/)?var/at/(tabs|jobs)/|"
                             r"/com\.apple\.TCC/TCC\.db$|^/(private/)?var/db/dslocal/nodes/Default/(users|groups)/")
FSE_LOGS = re.compile(r"^/(private/)?var/(log|audit)/|/(\.zsh_history|\.bash_history|\.zsh_sessions/.*)$|/Library/Logs/")
FSE_EXECUTABLE = re.compile(r"\.(app|pkg|dmg|sh|command|py|pl|rb|scpt|js|dylib|kext|so|bin|jar)(/|$)", re.I)
FSE_USER_CONTENT = re.compile(r"^/Users/[^/]+/(Downloads|Desktop)/|^/(private/)?(tmp|var/tmp)/|^/Users/Shared/")


def parse_fsevents(path, rel, *_):
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        data = gzip.decompress(raw)
    except (OSError, EOFError):
        data = raw
    page_name = os.path.basename(rel)
    off, n, total = 0, 0, 0
    while off + 12 <= len(data):
        magic = data[off:off + 4]
        if magic not in (b"1SLD", b"2SLD", b"3SLD"):
            break
        version = int(magic[:1])
        page_len = struct.unpack_from("<I", data, off + 8)[0]
        end = min(off + page_len, len(data))
        pos = off + 12
        while pos < end:
            z = data.find(b"\0", pos, end)
            if z < 0:
                break
            p = "/" + data[pos:z].decode("utf-8", "replace").lstrip("/")
            pos = z + 1
            if pos + 12 > end:
                break
            event_id, mask = struct.unpack_from("<QI", data, pos)
            pos += 12
            node = None
            if version >= 2:
                if pos + 8 > end:
                    break
                node = struct.unpack_from("<Q", data, pos)[0]
                pos += 8
            if version >= 3:
                pos += 4
            total += 1
            flags = [name for bit, name in FSE_FLAGS if mask & bit]
            found = []
            if FSE_PERSISTENCE.search(p) and set(flags) & {"Created", "Renamed", "Modified", "FolderCreated"}:
                found.append("persistence_path_change")
            if FSE_LOGS.search(p) and "Removed" in flags:
                found.append("log_or_history_deleted")
            if FSE_USER_CONTENT.search(p) and FSE_EXECUTABLE.search(p) and "Created" in flags:
                found.append("executable_created_in_user_or_temp")
            if not found and not (FSE_PERSISTENCE.search(p) or FSE_EXECUTABLE.search(p) and FSE_USER_CONTENT.search(p)):
                continue
            emit_record("mac_fsevent", f"{'/'.join(flags) or 'event'} {p}"[:300], path=p,
                        details=details(found, event_id=event_id, flags=",".join(flags), node_id=node, page=page_name))
            n += 1
            if n >= ROW_CAP:
                return
        off = end if end > off else len(data)


PARSERS = {
    "mac_accounts": parse_accounts,
    "mac_sudoers": lambda p, r, *_: lp.parse_sudoers(p, r),
    "mac_shell_history": lambda p, r, *_: lp.parse_shell_history(p, r),
    "mac_authorized_keys": lambda p, r, *_: lp.parse_authorized_keys(p, r),
    "mac_known_hosts": lambda p, r, *_: lp.parse_known_hosts(p, r),
    "mac_cron": lambda p, r, *_: lp.parse_cron(p, r),
    "mac_launch_item": parse_launch_item,
    "mac_plist": parse_plist,
    "mac_config_file": lambda p, r, *_: lp.parse_config_file(p, r),
    "mac_command_output": parse_command_output,
    "mac_processes": parse_processes,
    "mac_bodyfile": lambda p, r, *_: lp.parse_bodyfile(p, r),
    "mac_tcc": parse_tcc,
    "mac_quarantine": parse_quarantine,
    "mac_knowledgec": parse_knowledgec,
    "mac_xprotect": parse_xprotect,
    "mac_fsevents": parse_fsevents,
}


def main():
    if len(sys.argv) < 4:
        emit_error("usage: mac-parse.py <file> <role> <relative path> [wal] [shm]")
        return 1
    path, role, rel = sys.argv[1], sys.argv[2], sys.argv[3].replace("\\", "/")
    wal = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
    shm = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
    rel = re.sub(r"^(.*/)?MacArtifacts/", "", rel, flags=re.I)
    parser = PARSERS.get(role)
    if not parser:
        emit_error(f"unknown macOS artifact role: {role}")
        return 1
    try:
        parser(path, rel, wal, shm)
    except Exception as e:  # noqa: BLE001 — report and carry on with the other files
        emit_error(f"{rel}: {type(e).__name__}: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
