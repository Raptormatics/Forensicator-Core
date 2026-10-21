#!/usr/bin/env python3
"""
Windows Search, Windows 11 SQLite format — Windows.db (the property store;
Windows.edb's ESE successor, still handled by search-parse.py) and
Windows-gather.db (the gatherer's crawl list).

Invoked as: search-sqlite-parse.py <db> [wal] [shm]

The database is copied (with its -wal/-shm sidecars, when the collector
gathered them) into a private temp directory under the names SQLite
expects, so committed-but-uncheckpointed WAL frames are applied to the
COPY — the uploaded evidence file itself is never opened read-write.
Windows Search declares a custom collation (e.g.
UNICODE_en-US_LINGUISTIC_IGNORECASE); every collation named in the schema
is registered as a case-insensitive comparison so queries/indexes work.

Gather DB (SystemIndex_Gthr + SystemIndex_GthrPth, confirmed on a real
Windows 11 host): every crawled item's full path is rebuilt from the
GthrPth Scope -> Parent -> Name tree plus the item's FileName;
LastModified is an 8-byte little-endian FILETIME blob.

Property store (SystemIndex_1_PropertyStore{,_Metadata}): one row per
(WorkId, ColumnId, Value); _Metadata maps ColumnId to the canonical
property name (System.ItemPathDisplay, System.DateModified, ...). Rows are
pivoted per WorkId into one item with the forensically useful properties
(path, name, dates, size, owner, item type, search-content snippet).

Emits the same `search_entry` rows search-parse.py does
({table_name, record_index, details}) so results land in the existing
SearchIndexEntry table and tab.
"""
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile

from forensicator_records import emit, emit_error, filetime_to_iso

ROW_CAP = 500000


def open_copy(db, wal, shm):
    tmpdir = tempfile.mkdtemp(prefix="fz-search-")
    base = os.path.join(tmpdir, "search.db")
    shutil.copyfile(db, base)
    if wal:
        shutil.copyfile(wal, base + "-wal")
        if shm:
            shutil.copyfile(shm, base + "-shm")
    con = sqlite3.connect(base)
    sql = " ".join(r[0] or "" for r in con.execute("select sql from sqlite_master"))
    for name in set(re.findall(r"COLLATE\s+[\"'\[`]?([^\"'\]`\s,)]+)", sql, re.I)):
        con.create_collation(name, lambda a, b: (a.lower() > b.lower()) - (a.lower() < b.lower()))
    return con, tmpdir


def tables(con):
    return {r[0] for r in con.execute("select name from sqlite_master where type='table'")}


def filetime_blob(v):
    if isinstance(v, (bytes, bytearray)) and len(v) == 8:
        return filetime_to_iso(struct.unpack("<Q", v)[0])
    if isinstance(v, int):
        return filetime_to_iso(v)
    return None


def parse_gather(con):
    scopes = {}
    for scope, parent, name in con.execute("select Scope, Parent, Name from SystemIndex_GthrPth"):
        scopes[scope] = (parent, name or "")
    cache = {}

    def scope_path(scope):
        if scope in cache:
            return cache[scope]
        parts, seen, cur = [], set(), scope
        while cur in scopes and cur not in seen:
            seen.add(cur)
            parent, name = scopes[cur]
            parts.append(name)
            cur = parent
        p = "".join(reversed(parts))
        cache[scope] = p
        return p

    cols = [r[1] for r in con.execute("pragma table_info('SystemIndex_Gthr')")]
    wanted = [c for c in ("ScopeID", "FileName", "DocumentID", "LastModified", "DeletedCount", "CrawlNumberCrawled",
                          "FailureUpdateAttempts", "LastRequestedRunTime", "AppOwnerId") if c in cols]
    n = 0
    for row in con.execute(f"select {', '.join(wanted)} from SystemIndex_Gthr"):
        r = dict(zip(wanted, row))
        parent = scope_path(r.get("ScopeID"))
        name = r.get("FileName") or ""
        full = parent + name
        # "file:C:/[<volume guid>]/Users/x/a.txt" -> "C:\\Users\\x\\a.txt" for
        # readability and path rules; the raw gather URL is kept too.
        display = re.sub(r"^[a-z]+:(?=[A-Za-z]:)", "", full)
        display = re.sub(r"\[[0-9a-fA-F-]{36}\]/", "", display).replace("/", "\\")
        emit({"type": "search_entry", "table_name": "SystemIndex_Gthr", "record_index": n, "details": {
            "path": display, "gather_url": full, "file_name": name, "document_id": r.get("DocumentID"),
            "last_modified": filetime_blob(r.get("LastModified")), "deleted_count": r.get("DeletedCount"),
            "crawl_number": r.get("CrawlNumberCrawled"), "failure_attempts": r.get("FailureUpdateAttempts"),
        }})
        n += 1
        if n >= ROW_CAP:
            emit_error(f"gather row cap ({ROW_CAP}) reached")
            break


# Canonical property names worth surfacing per item, and the short key
# each is stored under in `details`.
PROPERTIES = {
    "System.ItemPathDisplay": "path", "System.ItemUrl": "url", "System.ItemName": "name",
    "System.ItemNameDisplay": "display_name", "System.FileName": "file_name", "System.ItemType": "item_type",
    "System.Kind": "kind", "System.Size": "size", "System.DateCreated": "created", "System.DateModified": "modified",
    "System.DateAccessed": "accessed", "System.DateImported": "imported", "System.FileOwner": "owner",
    "System.ItemAuthors": "authors", "System.Title": "title", "System.Search.AutoSummary": "content_snippet",
    "System.Message.FromAddress": "from", "System.Message.ToAddress": "to", "System.Message.Subject": "subject",
    "System.Link.TargetParsingPath": "link_target", "System.Search.Store": "store",
}
DATE_KEYS = {"created", "modified", "accessed", "imported"}


def decode_value(v, key):
    if v is None:
        return None
    if key in DATE_KEYS:
        return filetime_blob(v) or (str(v) if not isinstance(v, (bytes, bytearray)) else None)
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        if len(b) >= 2 and len(b) % 2 == 0 and b[1:2] == b"\x00":
            return b.decode("utf-16-le", errors="replace").rstrip("\x00")
        if key == "size" and len(b) == 8:
            return struct.unpack("<Q", b)[0]
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return b.hex()
    return v


def parse_property_store(con, names):
    store = next(t for t in names if re.fullmatch(r"SystemIndex_\d+_PropertyStore", t))
    meta = store + "_Metadata"
    if meta not in names:
        emit_error(f"{meta} missing — property names cannot be resolved")
        return
    mcols = [r[1] for r in con.execute(f"pragma table_info('{meta}')")]
    # Name holds the canonical "System.ItemPathDisplay" form; UniqueKey is
    # "4448-System_ItemPathDisplay" (confirmed on a real Windows 11 store).
    key_col = next((c for c in ("Name", "PropertyName", "UniqueKey") if c in mcols), None)
    if not key_col or "Id" not in mcols:
        emit_error(f"{meta} has no Id/UniqueKey columns ({mcols})")
        return
    colmap = {}
    for cid, key in con.execute(f"select Id, {key_col} from '{meta}'"):
        canon = str(key or "")
        if not canon.startswith("System."):
            canon = canon.split("-", 1)[-1].replace("_", ".")
        if canon in PROPERTIES:
            colmap[cid] = PROPERTIES[canon]
    if not colmap:
        emit_error("no known Windows Search properties found in the metadata table")
        return
    ids = ",".join(str(c) for c in colmap)
    current, item, n = None, {}, 0

    def flush():
        nonlocal n
        if current is not None and item:
            emit({"type": "search_entry", "table_name": store, "record_index": int(current), "details": {"work_id": current, **item}})
            n += 1

    for work_id, cid, value in con.execute(f"select WorkId, ColumnId, Value from '{store}' where ColumnId in ({ids}) order by WorkId"):
        if work_id != current:
            flush()
            if n >= ROW_CAP:
                emit_error(f"property store item cap ({ROW_CAP}) reached")
                return
            current, item = work_id, {}
        key = colmap[cid]
        val = decode_value(value, key)
        if key == "content_snippet" and isinstance(val, str):
            val = val[:2000]
        item[key] = val
    flush()


def main():
    if len(sys.argv) < 2:
        emit_error("usage: search-sqlite-parse.py <db> [wal] [shm]")
        sys.exit(1)
    db = sys.argv[1]
    wal = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
    shm = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
    tmpdir = None
    try:
        con, tmpdir = open_copy(db, wal, shm)
        names = tables(con)
        if "SystemIndex_Gthr" in names and "SystemIndex_GthrPth" in names:
            parse_gather(con)
        elif any(re.fullmatch(r"SystemIndex_\d+_PropertyStore", t) for t in names):
            parse_property_store(con, names)
        else:
            emit_error(f"not a recognized Windows Search SQLite database (tables: {sorted(names)[:20]})")
            sys.exit(1)
        con.close()
    except sqlite3.DatabaseError as e:
        emit_error(f"SQLite open failed: {e}")
        sys.exit(1)
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
