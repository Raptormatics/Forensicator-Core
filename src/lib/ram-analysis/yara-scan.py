#!/usr/bin/env python3
"""
Scans a raw memory image directly against a set of custom Yara rules —
no Volatility3 involvement, since Yara reports raw file offsets and mmap's
the file itself rather than loading it into memory (appropriate given this
box's limited RAM). Invoked as: yara-scan.py <image_path> <timeout_seconds>
Rules are read as a JSON array from stdin: [{"id": "...", "yaraSource": "..."}]
(stdin rather than argv — Yara rule source is multi-line and can be large,
argv escaping would be fragile).

Emits one JSON object per line to stdout:
  {"type": "not_installed"}                                    — yara-python missing, degrade gracefully
  {"type": "compile_error", "ruleId": ..., "message": ...}      — one rule's source didn't compile; others still run
  {"type": "match", "ruleId": ..., "ruleName": ..., "identifier": ..., "offset": ..., "matchedDataHex": ...}
  {"type": "error", "message": ...}                             — unrecoverable failure

Real yara-python 4.5.4 match-object shape confirmed by direct testing in
this environment: Rules.match(path) returns Match objects with .rule,
.namespace (== the sources dict key used at compile time — used here to
map a hit back to its originating RamYaraRule id), and .strings (a list
of StringMatch, each with .identifier and .instances, each instance
carrying .offset and .matched_data as raw bytes).
"""
import sys
import json

def emit(obj):
    print(json.dumps(obj), flush=True)

def main():
    if len(sys.argv) < 3:
        emit({"type": "error", "message": "usage: yara-scan.py <image_path> <timeout_seconds>"})
        sys.exit(1)
    image_path = sys.argv[1]
    timeout_seconds = int(sys.argv[2])

    try:
        import yara
    except ImportError:
        emit({"type": "not_installed"})
        sys.exit(0)

    try:
        rule_specs = json.load(sys.stdin)
    except Exception as e:
        emit({"type": "error", "message": f"invalid rules JSON on stdin: {e}"})
        sys.exit(1)

    valid_sources = {}
    for spec in rule_specs:
        rule_id = spec.get("id")
        source = spec.get("yaraSource", "")
        try:
            yara.compile(source=source)
            valid_sources[rule_id] = source
        except yara.SyntaxError as e:
            emit({"type": "compile_error", "ruleId": rule_id, "message": str(e)})

    if not valid_sources:
        sys.exit(0)

    try:
        combined = yara.compile(sources=valid_sources)
    except yara.SyntaxError as e:
        # Individually-valid rules can still collide when combined (e.g. duplicate
        # top-level rule names across two different RamYaraRule rows).
        emit({"type": "error", "message": f"rules compiled individually but not combined (duplicate rule name?): {e}"})
        sys.exit(1)

    try:
        matches = combined.match(image_path, timeout=timeout_seconds)
    except yara.TimeoutError:
        emit({"type": "error", "message": "yara scan timed out"})
        sys.exit(1)
    except Exception as e:
        emit({"type": "error", "message": str(e)})
        sys.exit(1)

    for m in matches:
        for s in m.strings:
            for inst in s.instances:
                emit({
                    "type": "match",
                    "ruleId": m.namespace,
                    "ruleName": m.rule,
                    "identifier": s.identifier,
                    "offset": inst.offset,
                    "matchedDataHex": inst.matched_data.hex(),
                })

if __name__ == "__main__":
    main()
