#!/usr/bin/env python3
"""
Linux artifacts from the Live Forensicator Linux collector's -A mode
(<host>/artifacts/LinuxArtifacts/ — see collector-layout.ts's
classifyLinuxPath()). Invoked as:

    linux-parse.py <file> <role> <path relative to LinuxArtifacts>

Files/<absolute path> holds raw copies mirrored at their real path, so the
original location is the relative path minus its "Files" prefix.

Every record's `details` starts with `findings` — a comma-separated list of
the suspicious traits found ("" when none) — which the built-in Linux rules
match through the rule subject's summary ("findings=...download_exec...").

Standard library only. Emits `record` rows (forensicator_records.py).
"""
import base64
import hashlib
import os
import re
import struct
import socket
import sys
from datetime import datetime, timezone

from forensicator_records import emit_error, emit_record, extract_iocs, first, read_text

ROW_CAP = 250000

# ── Suspicious command-line traits (shell history, cron, systemd, startup files)
COMMAND_TRAITS = [
    ("reverse_shell", re.compile(r"/dev/(tcp|udp)/|\bnc(at)?\b[^|;&]*\s-[a-z]*[ec]\b|socat\b.*\bexec:|bash\s+-i\b.*[>&]|mkfifo\b.*\bnc\b|python[0-9.]*\s+-c\s+.*socket|perl\s+-e\s+.*socket|php\s+-r\s+.*fsockopen", re.I)),
    ("download_exec", re.compile(r"(curl|wget|fetch)\b[^|;&]*\|\s*(ba|z|da|k)?sh\b|(curl|wget)\b[^;&]*(-o|-O|--output)\s*\S*(/tmp|/dev/shm|/var/tmp)[^;&]*[;&]+\s*(chmod|\./|/tmp|/dev/shm|/var/tmp|sh\b|bash\b)", re.I)),
    ("download", re.compile(r"\b(curl|wget|fetch|tftp)\b[^|;&\n]*(://|\b\d{1,3}(\.\d{1,3}){3}\b)", re.I)),
    ("encoded_exec", re.compile(r"base64\s+(-d|--decode)[^|;&]*\|\s*(ba|z)?sh\b|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64|eval\s*\(?\s*\$\(.*base64", re.I)),
    ("log_clearing", re.compile(r"(^|[;&|\s])(rm|shred|truncate)(\s+(-\S+|[0-9]+[KMG]?))*\s+\S*(/var/log/|_history(\s|$))|(?<![>0-9&])>(?!>)\s*/var/log/|journalctl\b[^;|]*--vacuum|\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|HISTSIZE=0", re.I)),
    ("mentions_temp_path", re.compile(r"(^|[\s;&|'\"=])(/tmp|/var/tmp|/dev/shm)/\S+", re.I)),
    ("persistence_change", re.compile(r"\bcrontab\s+(-e|-r|\S+\.\S+)|systemctl\s+(enable|daemon-reload)|>>?\s*\S*(authorized_keys|/etc/cron|\.bashrc|\.profile|/etc/profile|/etc/rc\.local|ld\.so\.preload)|\buseradd\b|\busermod\s+.*-aG\s*(sudo|wheel|root)\b|chattr\s+\+i", re.I)),
    ("recon", re.compile(r"\b(linpeas|linenum|les\.sh|pspy|lse\.sh|unix-privesc-check)\b|find\s+/\s+.*-perm\s+-?[0-9]*[46]000|cat\s+/etc/shadow|getcap\s+-r\s+/", re.I)),
    ("attack_tool", re.compile(r"\b(mimikatz|meterpreter|msfconsole|msfvenom|chisel|sliver|cobaltstrike|frpc|frps|dnscat|ligolo|xmrig|hydra|masscan|sqlmap)\b", re.I)),
    ("credential_access", re.compile(r"\b(sshpass\s+-p|mysql\s+.*-p\S+|PGPASSWORD=|AWS_SECRET_ACCESS_KEY=)", re.I)),
    ("container_escape", re.compile(r"docker\s+run\b.*(--privileged|-v\s+/:/|--pid=host)|nsenter\s+.*-t\s*1\b", re.I)),
]

TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
# Membership that amounts to root (docker/lxd/disk give it indirectly).
PRIVILEGED_GROUPS = {"root", "sudo", "wheel", "docker", "lxd", "lxc", "disk", "shadow", "admin"}
SYSTEM_EXE_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/")
STANDARD_TEMP_ENTRIES = {".X11-unix", ".ICE-unix", ".XIM-unix", ".font-unix", ".Test-unix", ".X0-lock", ".X1-lock"}


def traits(text):
    if not text:
        return []
    found = [name for name, rx in COMMAND_TRAITS if rx.search(text)]
    # A plain download is only worth naming when nothing stronger matched.
    if "download" in found and ("download_exec" in found or len(found) > 1):
        found.remove("download")
    return found


def details(findings, **kw):
    out = {"findings": ",".join(findings)}
    out.update({k: v for k, v in kw.items() if v is not None and v != ""})
    return out


def iso_epoch(value):
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v <= 0 or v > 4_102_444_800:
        return None
    return datetime.fromtimestamp(v, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def original_path(rel):
    rel = rel.replace("\\", "/")
    return "/" + rel[len("Files/"):] if rel.startswith("Files/") else rel


def owner_from_path(path):
    m = re.match(r"^/home/([^/]+)/", path)
    if m:
        return m.group(1)
    if path.startswith("/root/"):
        return "root"
    m = re.match(r"^/var/spool/cron/(?:crontabs/)?([^/]+)$", path)
    return m.group(1) if m else None


def text_lines(path):
    text, _enc = read_text(path)
    return text.splitlines()


def command_record(kind, title, line, path, user=None, timestamp=None, extra=None):
    found = traits(line)
    iocs = extract_iocs(line)
    emit_record(kind, title[:2000], timestamp=timestamp, path=path, user=user, process=line[:4000],
                url=first(iocs, "urls"), ip=first(iocs, "ips"),
                details=details(found, line=line[:4000], **(extra or {})))


# ── Accounts ─────────────────────────────────────────────────────────────
def parse_accounts(path, rel):
    orig = original_path(rel)
    name = os.path.basename(orig)
    for line in text_lines(path)[:ROW_CAP]:
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split(":")
        if name == "passwd" and len(f) >= 7:
            user, uid, gid, gecos, home, shell = f[0], f[2], f[3], f[4], f[5], f[6]
            found = []
            if uid == "0" and user != "root":
                found.append("uid0_non_root")
            login = not re.search(r"(nologin|false|sync|halt|shutdown)$", shell)
            if login and uid.isdigit() and 0 < int(uid) < 1000 and user not in ("sync",):
                found.append("system_account_with_shell")
            if f[1] not in ("x", "*", "!") and f[1]:
                found.append("password_hash_in_passwd")
            emit_record("linux_account", f"{user} (uid {uid})", path=home, user=user,
                        details=details(found, uid=uid, gid=gid, gecos=gecos, home=home, shell=shell, login_shell=login))
        elif name == "shadow" and len(f) >= 3:
            user, pw, last = f[0], f[1], f[2]
            found = []
            if pw == "":
                found.append("empty_password")
            locked = pw.startswith("!") or pw.startswith("*")
            algo = {"1": "md5", "2a": "bcrypt", "2b": "bcrypt", "2y": "bcrypt", "5": "sha256", "6": "sha512", "y": "yescrypt", "7": "scrypt"}.get(pw.split("$")[1] if pw.count("$") >= 2 else "", "")
            if algo == "md5":
                found.append("weak_password_hash")
            changed = iso_epoch(int(last) * 86400) if last.isdigit() else None
            emit_record("linux_shadow", f"{user}: {'locked' if locked else ('no password' if pw == '' else 'password set')}",
                        timestamp=changed, user=user,
                        details=details(found, has_password=bool(pw) and not locked, locked=locked, hash_algorithm=algo, last_change=changed))
        elif name in ("group", "gshadow") and len(f) >= 4:
            group, gid, members = f[0], f[2] if name == "group" else "", [m for m in f[3].split(",") if m]
            found = ["privileged_group_member"] if group in PRIVILEGED_GROUPS and members else []
            emit_record("linux_group", f"{group}: {', '.join(members) or '(no members)'}",
                        details=details(found, group=group, gid=gid, members=",".join(members)))


def parse_sudoers(path, rel):
    orig = original_path(rel)
    for n, line in enumerate(text_lines(path), 1):
        s = line.strip()
        if not s or (s.startswith("#") and not s.startswith(("#include", "#includedir"))):
            continue
        found = []
        if "NOPASSWD" in s:
            found.append("nopasswd")
        if re.search(r"\bALL\s*=\s*\(\s*ALL(\s*:\s*ALL)?\s*\)\s*(NOPASSWD:\s*)?ALL\b", s) and not re.match(r"^(root|%sudo|%admin|%wheel)\s", s):
            found.append("full_root_grant")
        if "!authenticate" in s or "env_keep" in s and "LD_PRELOAD" in s:
            found.append("weakened_sudo")
        emit_record("linux_sudoers", s[:500], path=orig, details=details(found, line_number=n, line=s))


# ── Login records (utmp/wtmp/btmp: 384-byte struct utmp) ─────────────────
UT_TYPES = {1: "RUN_LVL", 2: "BOOT_TIME", 5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS"}
UT_FMT = "<hxxi32s4s32s256shhiii4I20x"
UT_SIZE = struct.calcsize(UT_FMT)


def parse_login_records(path, rel):
    orig = original_path(rel)
    failed = "btmp" in os.path.basename(orig)
    with open(path, "rb") as fh:
        data = fh.read()
    dec = lambda b: b.split(b"\0", 1)[0].decode("utf-8", "replace")
    n = 0
    for off in range(0, len(data) - UT_SIZE + 1, UT_SIZE):
        t, pid, line, _id, user, host, _e1, _e2, _sess, sec, _usec, a0, a1, a2, a3 = struct.unpack_from(UT_FMT, data, off)
        if t not in UT_TYPES:
            continue
        addr = None
        try:
            if a0 and not (a1 or a2 or a3):
                addr = socket.inet_ntop(socket.AF_INET, struct.pack("<I", a0))
            elif a0 or a1 or a2 or a3:
                addr = socket.inet_ntop(socket.AF_INET6, struct.pack("<4I", a0, a1, a2, a3))
        except (OSError, ValueError):
            addr = None
        u, h = dec(user), dec(host)
        kind = "linux_failed_login" if failed else ("linux_login" if t in (6, 7) else "linux_login_event")
        title = f"{'FAILED ' if failed else ''}{UT_TYPES[t]} {u or '-'} on {dec(line) or '-'}" + (f" from {h}" if h else "")
        emit_record(kind, title, timestamp=iso_epoch(sec), user=u or None, ip=addr or (h if re.match(r"^[0-9.]+$|:", h or "") else None),
                    details=details([], type=UT_TYPES[t], tty=dec(line), host=h, pid=pid, source_file=orig))
        n += 1
        if n >= ROW_CAP:
            break


# ── Shell history ────────────────────────────────────────────────────────
def parse_shell_history(path, rel):
    orig = original_path(rel)
    user = owner_from_path(orig)
    name = os.path.basename(orig)
    lines = text_lines(path)
    pending_ts = None
    n = 0
    for line in lines:
        if not line.strip():
            continue
        ts = None
        cmd = line
        if name == ".bash_history" and re.match(r"^#\d{9,11}$", line):
            pending_ts = iso_epoch(line[1:])           # HISTTIMEFORMAT marker
            continue
        m = re.match(r"^: (\d{9,11}):\d+;(.*)$", line)   # zsh EXTENDED_HISTORY
        if m:
            ts, cmd = iso_epoch(m.group(1)), m.group(2)
        elif name == "fish_history":
            fm = re.match(r"^- cmd: (.*)$", line)
            if not fm:
                continue
            cmd = fm.group(1)
        elif name in (".viminfo", ".lesshst", ".wget-hsts"):
            if line.startswith(("#", "\"")) and name == ".viminfo":
                continue
        if pending_ts:
            ts, pending_ts = pending_ts, None
        n += 1
        command_record("linux_shell_history", cmd[:300], cmd, orig, user=user, timestamp=ts,
                       extra={"shell": name.lstrip("."), "line_number": n})
        if n >= ROW_CAP:
            break


# ── SSH ──────────────────────────────────────────────────────────────────
KEY_RE = re.compile(r"(?:^|\s)((?:sk-)?(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+)(?:@openssh\.com)?)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$")


def fingerprint(b64):
    try:
        digest = hashlib.sha256(base64.b64decode(b64)).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    except Exception:
        return None


def parse_authorized_keys(path, rel):
    orig = original_path(rel)
    user = owner_from_path(orig)
    for n, line in enumerate(text_lines(path), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = KEY_RE.search(s)
        options = s[:m.start(1)].strip() if m else ""
        found = []
        if re.search(r'(^|,)command="', options):
            found.append("forced_command")
        if re.search(r"(^|,)environment=", options):
            found.append("environment_option")
        if options and "from=" not in options and not found:
            found.append("key_options")
        if not orig.startswith(("/home/", "/root/")):
            found.append("unusual_location")
        comment = (m.group(3) or "").strip() if m else ""
        emit_record("linux_ssh_authorized_key", f"{m.group(1) if m else 'unparsed'} {comment}".strip(), path=orig, user=user,
                    process=options or None, ip=first(extract_iocs(options), "ips"),
                    details=details(found, key_type=m.group(1) if m else None, fingerprint=fingerprint(m.group(2)) if m else None,
                                    comment=comment, options=options, line_number=n))


def parse_known_hosts(path, rel):
    orig = original_path(rel)
    user = owner_from_path(orig)
    for line in text_lines(path)[:ROW_CAP]:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        hosts = parts[0] if parts else ""
        hashed = hosts.startswith("|1|")
        for h in ([hosts] if hashed else hosts.split(",")):
            hv = re.sub(r"^\[([^\]]+)\]:\d+$", r"\1", h)
            ip = hv if re.match(r"^[0-9.]+$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$", hv) else None
            emit_record("linux_ssh_known_host", "(hashed host)" if hashed else hv, path=orig, user=user, ip=ip,
                        details=details([], host=None if hashed else hv, hashed=hashed, key_type=parts[1] if len(parts) > 1 else None))


# ── Scheduled tasks, systemd, other config ───────────────────────────────
CRON_LINE = re.compile(r"^\s*(@\w+|(\S+\s+){5})(.*)$")


def parse_cron(path, rel):
    orig = original_path(rel)
    owner = owner_from_path(orig)
    is_script = re.match(r"^/etc/cron\.(hourly|daily|weekly|monthly)/", orig) is not None
    is_at = "/at" in orig and "/cron" not in orig
    for n, line in enumerate(text_lines(path), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if not is_script and not is_at:
            if re.match(r"^[A-Z_]+=", s):
                continue                                   # SHELL=, PATH=, MAILTO=
            m = CRON_LINE.match(s)
            if not m:
                continue
            schedule, command = m.group(1).strip(), m.group(3)
            user = owner
            if orig in ("/etc/crontab",) or orig.startswith("/etc/cron.d/"):
                sp = command.split(None, 1)
                user, command = (sp[0], sp[1] if len(sp) > 1 else "") if sp else (None, command)
            command_record("linux_cron_job", f"{schedule} {command}"[:300], command, orig, user=user,
                           extra={"schedule": schedule, "line_number": n})
        else:
            command_record("linux_cron_script", s[:300], s, orig, user=owner, extra={"line_number": n})


def parse_systemd_unit(path, rel):
    orig = original_path(rel)
    owner = owner_from_path(orig)
    exec_lines, section, desc = [], "", ""
    try:
        lines = text_lines(path)
    except Exception:
        lines = []
    for line in lines:
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s
        elif s.lower().startswith("description="):
            desc = s.split("=", 1)[1]
        elif re.match(r"^(Exec\w*|ExecStart\w*)=", s):
            exec_lines.append(s)
    name = os.path.basename(orig)
    if not exec_lines:
        if "generator" in orig:
            emit_record("linux_systemd_generator", name, path=orig, user=owner,
                        details=details(["generator"], file=orig))
        return
    for ex in exec_lines:
        cmd = ex.split("=", 1)[1].lstrip("@-+!:")
        found = traits(cmd)
        if owner:
            found.append("user_unit")
        if re.search(r"(^|/)\.[^/]+\.(service|timer)$", orig):
            found.append("hidden_unit_name")
        iocs = extract_iocs(cmd)
        emit_record("linux_systemd_unit", f"{name}: {cmd}"[:300], path=orig, user=owner, process=cmd[:4000],
                    url=first(iocs, "urls"), ip=first(iocs, "ips"),
                    details=details(found, unit=name, directive=ex.split("=", 1)[0], description=desc, exec=cmd[:4000]))


def parse_config_file(path, rel):
    """Startup files, loader/module/udev/PAM config, SSH config, sysctl, ...:
    every meaningful line, flagged where the location makes it suspicious."""
    orig = original_path(rel)
    owner = owner_from_path(orig)
    name = os.path.basename(orig)
    try:
        lines = text_lines(path)
    except Exception as e:
        emit_error(f"{orig}: {e}")
        return
    for n, line in enumerate(lines[:ROW_CAP], 1):
        s = line.strip()
        if not s or s.startswith(("#", ";", "//")):
            continue
        found = traits(s)
        if orig == "/etc/ld.so.preload":
            found.append("ld_preload_entry")
        # pam_exec runs a program on every authentication; a module loaded
        # by absolute path from outside the system library dirs is a
        # classic backdoor. (pam_permit is in Debian's stock stacks.)
        if orig.startswith("/etc/pam.d/") and re.search(r"pam_exec\.so|\s/(?!(usr/)?lib(64)?/)\S+\.so\b", s):
            found.append("pam_backdoor_candidate")
        if orig.startswith("/etc/udev/rules.d/") and "RUN+=" in s:
            found.append("udev_run")
        if orig.startswith("/etc/modprobe.d/") and re.match(r"^install\s+\S+\s+(?!/bin/(true|false))", s):
            found.append("modprobe_install_hook")
        if orig.startswith(("/etc/modules", "/etc/modules-load.d/")):
            found.append("autoload_module")
        if re.match(r"^(\S*/)?sshd_config", name) or "/sshd_config.d/" in orig:
            if re.match(r"^(PermitRootLogin\s+yes|PermitEmptyPasswords\s+yes|PasswordAuthentication\s+yes|AuthorizedKeysCommand\s)", s, re.I):
                found.append("weak_sshd_setting")
        # Stock hooks (update stamps, ESM) are everywhere; one that downloads,
        # runs from a temp/home dir or opens a shell is not.
        if orig.startswith(("/etc/apt/apt.conf.d/", "/etc/yum/pluginconf.d/")) and re.search(r"(Pre|Post)-Invoke|APT::Update::", s):
            if set(found) - {"mentions_temp_path"} or re.search(r"(/tmp|/var/tmp|/dev/shm|/home)/", s):
                found.append("package_manager_hook")
        if name in ("sysctl.conf",) or orig.startswith("/etc/sysctl.d/"):
            if re.match(r"^kernel\.core_pattern\s*=\s*\|", s):
                found.append("core_pattern_pipe")
        iocs = extract_iocs(s)
        emit_record("linux_config_line", f"{orig}: {s}"[:300], path=orig, user=owner, process=s[:4000],
                    url=first(iocs, "urls"), ip=first(iocs, "ips"),
                    details=details(found, file=orig, line_number=n, line=s[:4000]))


# ── Command output (Commands/*.txt and /proc copies) ─────────────────────
SS_RE = re.compile(r"^(tcp|udp|raw|sctp)\s+(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s*(.*)$")


def split_hostport(value):
    m = re.match(r"^\[?([^\]]*)\]?:([^:]+)$", value)
    if not m:
        return value, None
    host = re.sub(r"%\S+$", "", m.group(1))
    return host, m.group(2)


def parse_command_output(path, rel):
    orig = original_path(rel)
    name = os.path.basename(orig).rsplit(".", 1)[0] if rel.startswith("Commands/") else orig
    lines = text_lines(path)
    if name in ("sockets", "listening"):
        for line in lines[1:]:
            m = SS_RE.match(line.strip())
            if not m:
                continue
            proto, state, local, peer, rest = m.groups()
            lh, lp = split_hostport(local)
            ph, pp = split_hostport(peer)
            proc = re.search(r'users:\(\("([^"]+)",pid=(\d+)', rest)
            uid = re.search(r"\buid:(\d+)", rest)
            remote = ph if ph not in ("*", "0.0.0.0", "::", "[::]", "") else None
            found = []
            if state == "LISTEN" and lh not in ("127.0.0.1", "::1", "localhost") and not lh.startswith("127."):
                found.append("network_listener")
            if proc and proc.group(1) in ("bash", "sh", "dash", "zsh", "python", "python3", "perl", "nc", "ncat", "socat", "php"):
                found.append("shell_or_interpreter_socket")
            emit_record("linux_socket", f"{proto} {state} {local} -> {peer}" + (f" ({proc.group(1)})" if proc else ""),
                        process=proc.group(1) if proc else None, ip=remote,
                        details=details(found, protocol=proto, state=state, local=local, local_port=lp, remote=peer, remote_port=pp,
                                        pid=proc.group(2) if proc else None, uid=uid.group(1) if uid else None))
        return
    if name == "packages":
        for line in lines[:ROW_CAP]:
            f = line.split("\t")
            if len(f) >= 2:
                emit_record("linux_package", f"{f[0]} {f[1]}", details=details([], package=f[0], version=f[1],
                            arch=f[2] if len(f) > 2 else None, status=f[3] if len(f) > 3 else None))
        return
    if name == "symlinks":
        for line in lines[1:ROW_CAP]:
            f = line.split("\t")
            if len(f) < 2:
                continue
            link, target = f[0], f[1]
            resolved = f[2] if len(f) > 2 else ""
            found = []
            if re.search(r"(_history|\.history|fish_history)$", link) and resolved in ("/dev/null", ""):
                found.append("history_disabled")
            if any(resolved.startswith(t) for t in TEMP_DIRS) or "/home/" in resolved and "/systemd/" in link:
                found.append("link_to_unusual_location")
            emit_record("linux_symlink", f"{link} -> {target}", path=link,
                        details=details(found, link=link, target=target, resolved=resolved))
        return
    if name == "immutable":
        for line in lines:
            parts = line.split(None, 1)
            if len(parts) == 2:
                emit_record("linux_immutable_file", parts[1], path=parts[1],
                            details=details(["immutable_attribute"], attributes=parts[0]))
        return
    if name == "docker-inspect":
        import json
        try:
            containers = json.loads("\n".join(lines))
        except ValueError:
            containers = []
        for c in containers if isinstance(containers, list) else []:
            hc = c.get("HostConfig") or {}
            mounts = [m.get("Source", "") + ":" + m.get("Destination", "") for m in c.get("Mounts") or []]
            found = []
            if hc.get("Privileged"):
                found.append("privileged_container")
            if any(m.startswith("/:") or m.startswith("/var/run/docker.sock") or m.startswith("/run/docker.sock") for m in mounts):
                found.append("host_mount")
            if hc.get("PidMode") == "host" or hc.get("NetworkMode") == "host":
                found.append("host_namespace")
            cfg = c.get("Config") or {}
            cmd = " ".join((cfg.get("Entrypoint") or []) + (cfg.get("Cmd") or []))
            found += traits(cmd)
            emit_record("linux_container", f"{c.get('Name', '').lstrip('/')} ({cfg.get('Image', '')})",
                        timestamp=c.get("Created"), process=cmd or None,
                        details=details(found, image=cfg.get("Image"), privileged=bool(hc.get("Privileged")), mounts=",".join(mounts),
                                        state=(c.get("State") or {}).get("Status")))
        return
    if orig == "/proc/sys/kernel/tainted" or name == "/proc/sys/kernel/tainted":
        value = (lines[0] if lines else "0").strip()
        v = int(value) if value.isdigit() else 0
        found = [f for bit, f in ((12, "out_of_tree_module"), (13, "unsigned_module")) if v & (1 << bit)]
        emit_record("linux_kernel_taint", f"kernel taint {value}", details=details(found, taint=value))
        return
    if orig == "/proc/cmdline":
        s = " ".join(lines).strip()
        found = ["init_override"] if re.search(r"\binit=(?!/sbin/init\b|/lib/systemd/systemd\b|/usr/lib/systemd/systemd\b)", s) else []
        emit_record("linux_kernel_cmdline", s[:300], details=details(found, cmdline=s))
        return
    if name in ("bpf-programs",):
        for line in lines:
            if re.match(r"^\d+:", line):
                # systemd attaches its own programs (sd_*, sysctl_monitor, restrict_*).
                found = [] if re.search(r"\bname (sd_|sysctl_monitor|restrict_)", line) else ["non_systemd_bpf_program"]
                emit_record("linux_bpf_program", line.strip()[:300], details=details(found, line=line.strip()))
        return
    # Everything else: one record per line, so it is searchable and exportable.
    kind = "linux_cmd_" + re.sub(r"[^a-z0-9]+", "_", (name if rel.startswith("Commands/") else os.path.basename(orig)).lower()).strip("_")
    for n, line in enumerate(lines[:ROW_CAP], 1):
        if not line.strip():
            continue
        iocs = extract_iocs(line)
        emit_record(kind, line.strip()[:300], ip=first(iocs, "ips"), url=first(iocs, "urls"),
                    details=details([], line=line.rstrip()[:4000], line_number=n, source=orig))


# ── Processes ────────────────────────────────────────────────────────────
def parse_processes(path, rel):
    lines = text_lines(path)
    if not lines:
        return
    header = lines[0].split("\t")
    for line in lines[1:ROW_CAP]:
        f = line.split("\t")
        if len(f) < len(header):
            f += [""] * (len(header) - len(f))
        row = dict(zip(header, f))
        exe, cmd = row.get("exe", ""), row.get("cmdline", "")
        found = traits(cmd)
        if row.get("exe_deleted") == "1":
            found.append("deleted_executable")
        if any(exe.startswith(t) for t in TEMP_DIRS):
            found.append("exe_in_temp")
        if exe and re.search(r"/\.[^/]+$", exe):
            found.append("hidden_executable")
        comm = row.get("comm", "")
        # A process whose name doesn't match its executable is normal for
        # multi-call binaries and renamed titles — masquerading only when
        # the executable lives outside the system directories.
        if exe and comm and os.path.basename(exe)[:15] != comm[:15] and not exe.startswith(SYSTEM_EXE_DIRS):
            found.append("masquerade")
        emit_record("linux_process", f"{row.get('pid')} {comm} {cmd}"[:300], timestamp=row.get("start_utc") or None,
                    path=exe or None, user=row.get("user") or row.get("uid") or None, process=cmd[:4000] or comm,
                    sha256=row.get("exe_sha256") or None,
                    details=details(found, pid=row.get("pid"), ppid=row.get("ppid"), uid=row.get("uid"), comm=comm, cwd=row.get("cwd"),
                                    exe_deleted=row.get("exe_deleted") == "1"))


def parse_recovered_exe(path, rel):
    h256, h1, h5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    head = b""
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            if not head:
                head = chunk[:64]
            h256.update(chunk); h1.update(chunk); h5.update(chunk)
    ftype = "ELF" if head.startswith(b"\x7fELF") else ("script" if head.startswith(b"#!") else "data")
    m = re.match(r"^Processes/recovered/(\d+)_(.*)\.bin$", rel)
    emit_record("linux_recovered_executable", f"Recovered deleted executable: {m.group(2) if m else os.path.basename(rel)} (pid {m.group(1) if m else '?'})",
                path=rel, sha256=h256.hexdigest(), sha1=h1.hexdigest(), md5=h5.hexdigest(),
                details=details(["deleted_executable"], file_type=ftype, size=os.path.getsize(path), pid=m.group(1) if m else None))


# ── Filesystem timeline (TSK bodyfile) ───────────────────────────────────
def parse_bodyfile(path, rel):
    n = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            f = line.rstrip("\n").split("|")
            if len(f) < 11:
                continue
            name, mode, uid, gid, size = f[1], f[3], f[4], f[5], f[6]
            atime, mtime, ctime = f[7], f[8], f[9]
            found = []
            if mode[:1] == "-" and ("s" in mode[1:4].lower() or "s" in mode[4:7].lower()):
                if any(name.startswith(t) for t in TEMP_DIRS) or name.startswith(("/home/", "/root/")):
                    found.append("suid_in_user_or_temp_dir")
                else:
                    found.append("suid")
            if mode[:1] == "-" and "x" in mode and any(name.startswith(t) for t in TEMP_DIRS):
                found.append("executable_in_temp")
            if re.search(r"/\.\.?[^/]*$", name) and any(name.startswith(t) for t in TEMP_DIRS + ("/dev/",)) \
                    and os.path.basename(name) not in STANDARD_TEMP_ENTRIES:
                found.append("hidden_file_in_temp")
            if re.search(r"/(\.\.\.|\.\. |\s+)(/|$)", name):
                found.append("deceptive_name")
            emit_record("linux_fs_entry", name[:300], timestamp=iso_epoch(mtime), path=name,
                        details=details(found, mode=mode, uid=uid, gid=gid, size=size,
                                        accessed=iso_epoch(atime), changed=iso_epoch(ctime)))
            n += 1
            if n >= ROW_CAP:
                break


PARSERS = {
    "linux_accounts": parse_accounts,
    "linux_sudoers": parse_sudoers,
    "linux_login_records": parse_login_records,
    "linux_shell_history": parse_shell_history,
    "linux_authorized_keys": parse_authorized_keys,
    "linux_known_hosts": parse_known_hosts,
    "linux_cron": parse_cron,
    "linux_systemd_unit": parse_systemd_unit,
    "linux_config_file": parse_config_file,
    "linux_command_output": parse_command_output,
    "linux_processes": parse_processes,
    "linux_recovered_exe": parse_recovered_exe,
    "linux_bodyfile": parse_bodyfile,
}


def main():
    if len(sys.argv) < 4:
        emit_error("usage: linux-parse.py <file> <role> <relative path>")
        return 1
    path, role, rel = sys.argv[1], sys.argv[2], sys.argv[3].replace("\\", "/")
    rel = re.sub(r"^(.*/)?LinuxArtifacts/", "", rel, flags=re.I)
    parser = PARSERS.get(role)
    if not parser:
        emit_error(f"unknown Linux artifact role: {role}")
        return 1
    try:
        parser(path, rel)
    except Exception as e:  # noqa: BLE001 — report and carry on with the other files
        emit_error(f"{rel}: {type(e).__name__}: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
