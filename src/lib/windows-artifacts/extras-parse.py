#!/usr/bin/env python3
"""
Collector outputs outside WindowsArtifacts that have no dedicated Core
module (LOG4J scan results, GPResult HTML report, live-RAM triage HTML
tables and the clipboard capture) — see collector-layout.ts's
classifyHostExtra(). Invoked as: extras-parse.py <file> <relative path>
(relative to the host's artifacts folder, e.g. "RAM/LoadedModules.html").

  LOG4J/*.txt          one jar path per line that contains JndiLookup.class
                       (the collector's Log4Shell sweep) -> log4j_vulnerable_jar
  GroupPolicy/*.html   GPRESULT /H report: every table row with a setting
                       name and value -> gpo_report_setting (applied GPO
                       names, security settings, scripts, ...)
  RAM/<Table>.html     ProcessMemoryMap/LoadedModules/NetworkConnections/
                       NamedPipes: each HTML table row keyed by its header
                       -> ram_<table> with path/ip/process columns filled
                       when a recognizable column exists
  RAM/Clipboard.txt    the clipboard text at collection time -> clipboard_text

Standard library only (html.parser). Emits `record` rows.
"""
import os
import re
import sys
from html.parser import HTMLParser

from forensicator_records import emit_error, emit_record, extract_iocs, first, read_text

ROW_CAP = 20000


class TableParser(HTMLParser):
    """Collects every <table> as [header cells, rows of cells]."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables, self._table, self._row, self._cell, self._in_cell = [], None, None, [], False

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._in_cell, self._cell = True, []

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._in_cell:
            self._row.append(" ".join("".join(self._cell).split()))
            self._in_cell = False
        elif tag == "tr" and self._row is not None and self._table is not None:
            if any(c for c in self._row):
                self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            if self._table:
                self.tables.append(self._table)
            self._table = None

    def handle_data(self, data):
        if self._in_cell:
            self._cell.append(data)


def tables_of(path):
    text, _ = read_text(path)
    p = TableParser()
    p.feed(text)
    return p.tables


def parse_log4j(path, rel):
    text, _ = read_text(path)
    for line in text.splitlines():
        jar = line.strip()
        if jar:
            emit_record("log4j_vulnerable_jar", f"JndiLookup.class present in {jar}", path=jar,
                        details={"source_file": rel, "note": "Jar contains JndiLookup.class — check the Log4j version for CVE-2021-44228/45046"})


def parse_gpo(path, rel):
    n = 0
    for table in tables_of(path):
        for row in table:
            cells = [c for c in row if c]
            if len(cells) < 2:
                continue
            setting, value = cells[0], " | ".join(cells[1:])
            iocs = extract_iocs(value)
            emit_record("gpo_report_setting", f"{setting}: {value[:250]}", path=first(iocs, "paths"),
                        details={"source_file": rel, "setting": setting, "value": value[:2000], "cells": cells[:12]})
            n += 1
            if n >= ROW_CAP:
                emit_error("GPO report row cap reached")
                return


PATH_COLS = re.compile(r"^(path|image ?path|module ?path|executable|file ?name|fullname|module|filename)$", re.I)
IP_COLS = re.compile(r"(remote|foreign).*(address|ip)|^remoteaddress$", re.I)
PROC_COLS = re.compile(r"^(process|process ?name|name|owning ?process)$", re.I)


def parse_ram_table(path, rel):
    table_name = re.sub(r"[^a-z0-9]+", "_", os.path.splitext(os.path.basename(rel))[0].lower()).strip("_")
    n = 0
    for table in tables_of(path):
        header, rows = table[0], table[1:]
        for row in rows:
            rec = {header[i] if i < len(header) and header[i] else f"col{i}": v for i, v in enumerate(row)}
            pick = lambda rx: next((v for k, v in rec.items() if rx.search(k) and v), None)
            ip = pick(IP_COLS)
            emit_record(f"ram_{table_name}", " | ".join(v for v in row if v)[:300], path=pick(PATH_COLS),
                        process=pick(PROC_COLS), ip=ip.rsplit(":", 1)[0] if ip and ip.count(":") == 1 else ip,
                        details={"source_file": rel, "row": rec})
            n += 1
            if n >= ROW_CAP:
                emit_error("RAM table row cap reached")
                return


def parse_clipboard(path, rel):
    text, _ = read_text(path, 8 * 1024 * 1024)
    if not text.strip():
        return
    iocs = extract_iocs(text)
    emit_record("clipboard_text", f"Clipboard at collection time: {text.strip()[:200]}",
                url=first(iocs, "urls"), ip=first(iocs, "ips"),
                details={"source_file": rel, "content": text[:8000], "content_length": len(text), "iocs": iocs,
                         "mentions_credentials": bool(re.search(r"pass(word|wd)?|pwd|secret|api[_-]?key|token|credential", text, re.I))})


def main():
    if len(sys.argv) < 3:
        emit_error("usage: extras-parse.py <file> <relative path>")
        sys.exit(1)
    path, rel = sys.argv[1], sys.argv[2]
    top = rel.replace("\\", "/").split("/")[0].lower()
    name = os.path.basename(rel).lower()
    try:
        if top == "log4j":
            parse_log4j(path, rel)
        elif top == "grouppolicy":
            parse_gpo(path, rel)
        elif top == "ram" and name == "clipboard.txt":
            parse_clipboard(path, rel)
        elif top == "ram":
            parse_ram_table(path, rel)
        else:
            emit_error(f"no extras parser for {rel}")
    except Exception as e:
        emit_error(f"{rel}: parse failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
