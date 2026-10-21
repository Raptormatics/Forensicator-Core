#!/usr/bin/env python3
"""
Raw-content artifacts the collector acquires opt-in:

  recycle_payload — Recycle Bin $R<id> files (the deleted file's actual
      content). Hashed (SHA-256/SHA-1/MD5, streamed), type-sniffed from magic
      bytes; the TypeScript side upserts the SHA-256 into the shared IOC
      table (threat-intel lookup) and runs the RAM YARA ruleset over the
      file. The matching $I file (same suffix) carries the original path.

  memory_file — pagefile.sys / swapfile.sys / hiberfil.sys. Streamed in
      chunks for indicator strings (URLs, e-mail addresses, UNC paths,
      PowerShell download/encoded-command fragments), counted per unique
      value. Pagefile/swapfile pages are stored uncompressed, so this
      recovers real content (command lines, URLs from evicted process
      memory). hiberfil.sys on Windows 8+ is Xpress-compressed: the header
      signature/version is reported, and only the small uncompressed
      portions yield strings — full analysis needs it decompressed into a
      raw image first (volatility3 on this appliance has no hibernation
      layer), which the emitted note says plainly.

Invoked as: payload-parse.py <file> <recycle_payload|memory_file> <relative path>
Emits `record` rows (kinds recycle_payload | memory_ioc | memory_file_info).
"""
import hashlib
import os
import re
import sys

from forensicator_records import emit_error, emit_record

CHUNK = 16 * 1024 * 1024
OVERLAP = 4096
IOC_CAP = 5000

MAGIC = [
    (b"MZ", "PE executable"), (b"%PDF", "PDF"), (b"PK\x03\x04", "ZIP/OOXML"), (b"\xd0\xcf\x11\xe0", "OLE2 (legacy Office/MSI)"),
    (b"\x7fELF", "ELF"), (b"Rar!", "RAR"), (b"7z\xbc\xaf", "7-Zip"), (b"\x1f\x8b", "gzip"), (b"\x89PNG", "PNG"),
    (b"\xff\xd8\xff", "JPEG"), (b"GIF8", "GIF"), (b"{\\rtf", "RTF"), (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (LNK)"),
    (b"<?xml", "XML"), (b"#!", "script (shebang)"),
]


def sniff(head):
    for magic, label in MAGIC:
        if head.startswith(magic):
            return label
    sample = head[:512]
    if sample and all(b in b"\t\r\n" or 32 <= b < 127 for b in sample):
        text = sample.decode("ascii", "replace").lower()
        if any(k in text for k in ("powershell", "invoke-", "iex", "frombase64string")):
            return "PowerShell script"
        if text.lstrip().startswith(("@echo", "echo ", "set ", "rem ")):
            return "batch script"
        return "text"
    return "unknown"


def recycle_payload(path, rel):
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    size = 0
    with open(path, "rb") as fh:
        head = fh.read(4096)
        chunk = head
        while chunk:
            sha256.update(chunk); sha1.update(chunk); md5.update(chunk)
            size += len(chunk)
            chunk = fh.read(CHUNK)
    name = os.path.basename(rel)
    emit_record(
        "recycle_payload", f"Recycle Bin payload {name} ({sniff(head)}, {size} bytes)",
        path=rel, sha256=sha256.hexdigest(), sha1=sha1.hexdigest(), md5=md5.hexdigest(),
        details={"file_type": sniff(head), "size_bytes": size, "payload_name": name,
                 "metadata_file": "$I" + name[2:] if name.upper().startswith("$R") else None},
    )


PATTERNS = [
    ("url", re.compile(rb"(?:https?|ftp)://[\x21-\x7e]{4,300}")),
    ("email", re.compile(rb"[A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]{2,128}\.[A-Za-z]{2,12}")),
    ("unc_path", re.compile(rb"\\\\[A-Za-z0-9._$-]{2,64}\\[\x21-\x7e]{2,200}")),
    ("powershell", re.compile(rb"(?i)(?:powershell(?:\.exe)?\s+[\x20-\x7e]{0,40}-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|"
                              rb"iex\s*\(\s*(?:new-object|\(new-object)[\x20-\x7e]{10,200}|downloadstring\([\x20-\x7e]{5,200}\)|"
                              rb"invoke-(?:webrequest|expression|mimikatz|shellcode)[\x20-\x7e]{0,200})")),
]
TRAIL = b"\"'<>)]}.,; \t"


UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def scan_buffer(buf, counts, first_seen, base):
    def hit(kind, raw, offset, encoding):
        value = raw.rstrip(TRAIL).decode("ascii", "replace")
        key = (kind, value)
        counts[key] = counts.get(key, 0) + 1
        if key not in first_seen:
            first_seen[key] = (offset, encoding)

    for kind, rx in PATTERNS:
        for m in rx.finditer(buf):
            hit(kind, m.group(), base + m.start(), "ascii")
    # UTF-16LE: scan each printable run with its NULs dropped, so text that
    # is ASCII in the page isn't counted twice.
    for run in UTF16_RUN.finditer(buf):
        narrow = run.group()[::2]
        for kind, rx in PATTERNS:
            for m in rx.finditer(narrow):
                hit(kind, m.group(), base + run.start() + 2 * m.start(), "utf16")


def memory_file(path, rel):
    name = os.path.basename(rel).lower()
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(4096)
    signature = head[:4].decode("ascii", "replace")
    info = {"file": name, "size_bytes": size, "signature": signature}
    if name.startswith("hiberfil"):
        info["note"] = ("hiberfil.sys is Xpress-compressed on Windows 8+ (signature "
                        f"'{signature}'); only uncompressed regions were string-scanned. Decompress it to a raw "
                        "memory image (e.g. volatility3's windows.hibernation plugins or hibr2bin) and upload that "
                        "image to RAM Analysis for full analysis.")
    elif signature.lower() in ("hibr", "wake", "rstr"):
        info["note"] = "Unexpected hibernation signature on a non-hiberfil file"
    emit_record("memory_file_info", f"{name}: {size} bytes, signature {signature!r}", path=rel, details=info)

    counts, first_seen = {}, {}
    with open(path, "rb") as fh:
        base = 0
        carry = b""
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            scan_buffer(carry + chunk, counts, first_seen, base - len(carry))
            carry = chunk[-OVERLAP:]
            base += len(chunk)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], first_seen[kv[0]][0]))
    for (kind, value), count in ranked[:IOC_CAP]:
        offset, encoding = first_seen[(kind, value)]
        emit_record(
            "memory_ioc", f"{kind}: {value[:300]}",
            url=value if kind == "url" else None, path=value if kind == "unc_path" else None,
            details={"indicator_type": kind, "value": value, "occurrences": count, "first_offset": offset,
                     "encoding": encoding, "source": name},
        )
    if len(ranked) > IOC_CAP:
        emit_error(f"{len(ranked)} unique indicators found; the {IOC_CAP} most frequent were kept")


def main():
    if len(sys.argv) < 4:
        emit_error("usage: payload-parse.py <file> <recycle_payload|memory_file> <relative path>")
        sys.exit(1)
    path, mode, rel = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        if mode == "recycle_payload":
            recycle_payload(path, rel)
        else:
            memory_file(path, rel)
    except Exception as e:
        emit_error(f"payload parse failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
