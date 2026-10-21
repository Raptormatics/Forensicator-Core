"""
Shared helpers for the Stage-2 Windows Artifact parsers that emit generic
`record` rows (ArtifactRecordEntry — see windows-artifacts.prisma and
record-engine.ts): JSON-lines emission, UTF-16/ASCII string carving,
FILETIME / ULEB128 decoding, and IOC extraction from free text.

Imported by sibling scripts (wmi-parse.py, defender-history-parse.py,
app-artifact-parse.py, logfile-parse.py, payload-parse.py, ...) — they are
spawned as `python3 <script>` so this directory is on sys.path[0].
Standard library only.

Record protocol (one JSON object per stdout line):
  {"type": "record", "kind": str, "title": str, "timestamp": iso|None,
   "path": str|None, "user": str|None, "process": str|None, "url": str|None,
   "ip": str|None, "sha256": str|None, "sha1": str|None, "md5": str|None,
   "details": {...}}
  {"type": "error", "message": str}
"""
import json
import re
import struct
from datetime import datetime, timedelta, timezone

FILETIME_MIN = 116444736000000000   # 1970-01-01
FILETIME_MAX = 139000000000000000   # ~2041 — anything past this is not a real timestamp


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def emit_error(message):
    emit({"type": "error", "message": str(message)[:1000]})


def emit_record(kind, title, timestamp=None, path=None, user=None, process=None, url=None,
                ip=None, sha256=None, sha1=None, md5=None, details=None):
    emit({
        "type": "record", "kind": kind, "title": (title or "")[:2000], "timestamp": timestamp,
        "path": path, "user": user, "process": process, "url": url, "ip": ip,
        "sha256": sha256.lower() if sha256 else None,
        "sha1": sha1.lower() if sha1 else None,
        "md5": md5.lower() if md5 else None,
        "details": details or {},
    })


def filetime_to_iso(value):
    """Integer FILETIME (100ns since 1601) -> ISO-8601 UTC with Z, or None."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    if not (FILETIME_MIN <= value <= FILETIME_MAX):
        return None
    return (datetime(1601, 1, 1) + timedelta(microseconds=value / 10)).isoformat() + "Z"


def filetime_bytes_to_iso(raw, offset=0):
    if raw is None or len(raw) < offset + 8:
        return None
    return filetime_to_iso(struct.unpack_from("<Q", raw, offset)[0])


def epoch_ms_to_iso(ms):
    try:
        ms = int(ms)
    except (TypeError, ValueError):
        return None
    if not (0 < ms < 2_200_000_000_000):
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def read_uleb128(buf, offset):
    """Returns (value, next_offset); raises IndexError past the end."""
    result = shift = 0
    while True:
        byte = buf[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return result, offset
        if shift > 63:
            raise ValueError("ULEB128 too long")


UTF16_RE = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){4,}")
ASCII_RE = re.compile(rb"[\x09\x20-\x7e]{4,}")


def utf16_strings(buf, min_chars=4):
    """[(offset, text)] of little-endian UTF-16 printable runs."""
    out = []
    for m in UTF16_RE.finditer(buf):
        text = m.group().decode("utf-16-le", errors="replace")
        if len(text) >= min_chars:
            out.append((m.start(), text))
    return out


def ascii_strings(buf, min_chars=4):
    return [(m.start(), m.group().decode("ascii", errors="replace")) for m in ASCII_RE.finditer(buf) if len(m.group()) >= min_chars]


# ── IOC extraction ──────────────────────────────────────────────────────────

URL_RE = re.compile(r"\b(?:https?|ftp|ftps|wss?)://[^\s\"'<>\]\[(){}|\\^`]{3,}", re.I)
IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
WINPATH_RE = re.compile(r"(?:\b[A-Za-z]:\\|\\\\[A-Za-z0-9._$-]+\\)[^\r\n\"<>|*?]{2,260}")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
ISO_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,7})?(?:Z|[+-]\d{2}:?\d{2})?)")

# Addresses that are never meaningful indicators on their own.
_IGNORED_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


def extract_iocs(text):
    """Returns a dict of the IOC kinds found in `text` (each a de-duplicated
    list, first-seen order, capped) — used for both record columns and the
    `iocs` detail block."""
    if not text:
        return {}
    found = {}

    def add(kind, values, cap=50):
        seen = []
        for v in values:
            v = v.rstrip(".,;:)")
            if v and v not in seen:
                seen.append(v)
            if len(seen) >= cap:
                break
        if seen:
            found[kind] = seen

    add("urls", URL_RE.findall(text))
    add("ips", [ip for ip in IPV4_RE.findall(text) if ip not in _IGNORED_IPS and not ip.startswith("0.")])
    add("emails", EMAIL_RE.findall(text))
    add("paths", [p.strip() for p in WINPATH_RE.findall(text)])
    add("sha256", SHA256_RE.findall(text))
    sha256_set = set(found.get("sha256", []))
    add("sha1", [h for h in SHA1_RE.findall(text) if not any(h in s for s in sha256_set)])
    return found


def first(found, kind):
    values = found.get(kind)
    return values[0] if values else None


def parse_line_timestamp(line, assume_utc=False):
    """First ISO-like timestamp near the start of a log line. Without an
    explicit offset the zone is unknown; assume_utc=True appends "Z" for
    sources known to log in UTC (otherwise JS `new Date()` would silently
    read it as the Core server's local time)."""
    m = ISO_TS_RE.search(line[:80])
    if not m:
        return None
    raw = m.group(1).replace(" ", "T", 1).replace(",", ".")
    # Trim >6 fractional digits (Defender/.NET emit 7) so JS Date can parse it.
    raw = re.sub(r"(\.\d{6})\d+", r"\1", raw)
    if assume_utc and not re.search(r"(Z|[+-]\d{2}:?\d{2})$", raw):
        raw += "Z"
    return raw


def read_text(path, max_bytes=64 * 1024 * 1024):
    """Reads a log/text file whatever its encoding: UTF-16 (BOM or
    NUL-interleaved, as Defender's Support logs are), UTF-8 with/without
    BOM, falling back to latin-1. Returns (text, encoding)."""
    with open(path, "rb") as fh:
        raw = fh.read(max_bytes)
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace"), "utf-16"
    if len(raw) >= 4 and raw[1] == 0 and raw[3] == 0 and raw[0] != 0:
        return raw.decode("utf-16-le", errors="replace"), "utf-16-le"
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace"), "utf-8-sig"
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("latin-1"), "latin-1"


def looks_binary(path, sample=4096):
    with open(path, "rb") as fh:
        head = fh.read(sample)
    if not head:
        return False
    if head.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return False
    if len(head) >= 4 and head[1] == 0 and head[3] == 0:
        return False  # UTF-16LE text without BOM
    control = sum(1 for b in head if b < 9 or 13 < b < 32)
    return control / len(head) > 0.1
