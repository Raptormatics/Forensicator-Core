#!/usr/bin/env python3
"""
WMI permanent event subscriptions — the collector's
WMI\\PermanentSubscriptions.json (root\\subscription __EventFilter /
__EventConsumer / __FilterToConsumerBinding instances, serialized by
PowerShell's ConvertTo-Json from Get-CimInstance) — and, best-effort, raw
WBEM repository files (WMI\\Repository\\OBJECTS.DATA etc.).

Invoked as: wmi-parse.py <file> <mode>   (mode: subscriptions | repository)

Subscriptions JSON quirks, confirmed against a real Windows 11 export:
  - each class key holds a bare object (not a 1-element array) when only one
    instance exists;
  - __EventConsumer rows are flattened instance properties with no class
    name, so the consumer type is inferred from which type-specific
    properties are present (CommandLineTemplate -> CommandLineEventConsumer,
    ScriptText/ScriptFileName -> ActiveScriptEventConsumer, ...);
  - binding Consumer/Filter references are nested CimInstance objects whose
    CimSystemProperties.ClassName holds the real consumer class and whose
    CimInstanceProperties carry the referenced instance's Name.

Repository mode carves the raw (undocumented, page-based) repository for
consumer/binding instance text — the same technique as
PyWMIPersistenceFinder — so a subscription deleted from the live namespace
but not yet overwritten on disk can still surface. Carved rows are marked
`carved`.

Emits `record` rows (see forensicator_records.py) with kinds
wmi_filter | wmi_consumer | wmi_binding | wmi_repository_hit.
"""
import json
import re
import sys

from forensicator_records import emit_error, emit_record, extract_iocs, first, utf16_strings, ascii_strings

# Built-in subscriptions Windows/OEM software create on clean installs —
# reported, but not marked suspicious.
KNOWN_BENIGN_NAMES = {
    "scm event log filter", "scm event log consumer",
    "bvtfilter", "bvtconsumer",
    "microsoft-windows-wmi-activity", "dellcommandmonitor",
}

CONSUMER_TYPES = [
    ("CommandLineTemplate", "CommandLineEventConsumer"),
    ("ExecutablePath", "CommandLineEventConsumer"),
    ("ScriptText", "ActiveScriptEventConsumer"),
    ("ScriptFileName", "ActiveScriptEventConsumer"),
    ("ScriptingEngine", "ActiveScriptEventConsumer"),
    ("SMTPServer", "SMTPEventConsumer"),
    ("FileName", "LogFileEventConsumer"),
    ("SourceName", "NTEventLogEventConsumer"),
]

SUSPICIOUS_TYPES = {"CommandLineEventConsumer", "ActiveScriptEventConsumer"}


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def sid_from_bytes(arr):
    try:
        b = bytes(arr)
        count = b[1]
        authority = int.from_bytes(b[2:8], "big")
        subs = [int.from_bytes(b[8 + 4 * i:12 + 4 * i], "little") for i in range(count)]
        return "S-1-%d%s" % (authority, "".join("-%d" % s for s in subs))
    except Exception:
        return None


def consumer_type(props):
    for key, ctype in CONSUMER_TYPES:
        if props.get(key) not in (None, "", []):
            return ctype
    return "EventConsumer"


def cim_ref(obj):
    """Nested CimInstance reference -> (class name, Name property)."""
    if not isinstance(obj, dict):
        return None, None
    cls = (obj.get("CimSystemProperties") or {}).get("ClassName") or (obj.get("CimClass") or {}).get("CimClassName")
    name = None
    for p in as_list(obj.get("CimInstanceProperties")):
        if isinstance(p, dict) and p.get("Name") == "Name":
            name = p.get("Value")
    return cls, name


def parse_subscriptions(path):
    with open(path, "rb") as fh:
        data = json.loads(fh.read().decode("utf-8-sig", errors="replace"))
    if not isinstance(data, dict):
        emit_error("PermanentSubscriptions.json is not an object")
        return

    for f in as_list(data.get("__EventFilter")):
        if not isinstance(f, dict):
            continue
        name = f.get("Name") or ""
        query = f.get("Query") or ""
        emit_record(
            "wmi_filter", f"Event filter '{name}': {query}",
            path=None, user=sid_from_bytes(f.get("CreatorSID") or []),
            details={
                "name": name, "query": query, "query_language": f.get("QueryLanguage"),
                "event_namespace": f.get("EventNamespace"),
                "known_benign": name.lower() in KNOWN_BENIGN_NAMES,
            },
        )

    for c in as_list(data.get("__EventConsumer")):
        if not isinstance(c, dict):
            continue
        name = c.get("Name") or ""
        ctype = consumer_type(c)
        action = c.get("CommandLineTemplate") or c.get("ExecutablePath") or c.get("ScriptText") or c.get("ScriptFileName") or c.get("FileName") or c.get("SourceName") or ""
        benign = name.lower() in KNOWN_BENIGN_NAMES
        iocs = extract_iocs(str(action))
        emit_record(
            "wmi_consumer", f"{ctype} '{name}': {str(action)[:500]}",
            path=str(action)[:2000] if ctype in SUSPICIOUS_TYPES and action else None,
            user=sid_from_bytes(c.get("CreatorSID") or []),
            url=first(iocs, "urls"), ip=first(iocs, "ips"),
            details={
                "name": name, "consumer_type": ctype, "action": action,
                "scripting_engine": c.get("ScriptingEngine"), "working_directory": c.get("WorkingDirectory"),
                "suspicious_type": ctype in SUSPICIOUS_TYPES and not benign,
                "known_benign": benign, "iocs": iocs,
            },
        )

    for b in as_list(data.get("__FilterToConsumerBinding")):
        if not isinstance(b, dict):
            continue
        ccls, cname = cim_ref(b.get("Consumer"))
        fcls, fname = cim_ref(b.get("Filter"))
        benign = (cname or "").lower() in KNOWN_BENIGN_NAMES
        emit_record(
            "wmi_binding", f"Binding: filter '{fname}' -> {ccls or 'consumer'} '{cname}'",
            user=sid_from_bytes(b.get("CreatorSID") or []),
            details={
                "consumer_class": ccls, "consumer_name": cname, "filter_name": fname,
                "suspicious_type": (ccls in SUSPICIOUS_TYPES) and not benign,
                "known_benign": benign,
            },
        )


REPO_MARKERS = ("CommandLineEventConsumer", "ActiveScriptEventConsumer", "__FilterToConsumerBinding", "__EventFilter")
REPO_CONTEXT = 600


def parse_repository(path):
    with open(path, "rb") as fh:
        buf = fh.read()
    seen = set()
    hits = 0
    for offset, text in ascii_strings(buf, 6) + utf16_strings(buf, 6):
        marker = next((m for m in REPO_MARKERS if m in text), None)
        if not marker:
            continue
        # The interesting values (consumer command line, script, filter
        # query) sit in the instance record right after the class name.
        window = buf[offset:offset + REPO_CONTEXT]
        context = [t for _, t in ascii_strings(window, 4)] + [t for _, t in utf16_strings(window, 4)]
        snippet = " | ".join(dict.fromkeys(context))[:1500]
        key = (marker, snippet[:300])
        if key in seen:
            continue
        seen.add(key)
        iocs = extract_iocs(snippet)
        suspicious = marker in SUSPICIOUS_TYPES and not any(n in snippet.lower() for n in KNOWN_BENIGN_NAMES)
        emit_record(
            "wmi_repository_hit", f"{marker} in WBEM repository: {snippet[:300]}",
            path=first(iocs, "paths") if suspicious else None, url=first(iocs, "urls"), ip=first(iocs, "ips"),
            details={"marker": marker, "offset": offset, "context": snippet, "carved": True,
                     "suspicious_type": suspicious, "iocs": iocs},
        )
        hits += 1
        if hits >= 2000:
            break


def main():
    if len(sys.argv) < 3:
        emit_error("usage: wmi-parse.py <file> <subscriptions|repository>")
        sys.exit(1)
    path, mode = sys.argv[1], sys.argv[2]
    try:
        if mode == "subscriptions":
            parse_subscriptions(path)
        else:
            parse_repository(path)
    except Exception as e:
        emit_error(f"WMI parse failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
