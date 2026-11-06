#!/usr/bin/env python3
"""Strictly publish only the native public-fixture protection schema."""
import json
import sys
from pathlib import Path

DOMAINS = {"NSCocoaErrorDomain", "NSPOSIXErrorDomain", "NSOSStatusErrorDomain", "NSMachErrorDomain", "other"}
CODES = {-50, -4, 0, 1, 2, 4, 5, 13, 22, 45, 95, 257, 260, 262, 512, 513, 516, 640, 642, 3328, 4097, 4099, "other"}


def step(value, field=None, choices=()):
    if not isinstance(value, dict) or value.get("status") not in {"ok", "error"}:
        return {"status": "missing"}
    if value["status"] == "error":
        domain, code = value.get("domain"), value.get("code")
        return {"status": "error", "domain": domain if domain in DOMAINS else "other", "code": code if type(code) in {int, str} and code in CODES else "other"}
    output = {"status": "ok"}
    if field is not None:
        output[field] = value.get(field) if value.get(field) in choices else "unknown"
    return output


def protection(value):
    output = step(value)
    if output["status"] == "ok":
        output["representation"] = value.get("representation") if value.get("representation") in {"typed", "string", "missing", "other"} else "other"
        output["class"] = value.get("class") if value.get("class") in {"complete", "weaker", "unknown"} else "unknown"
    return output


def sanitize(value):
    if not isinstance(value, dict) or value.get("version") != 1:
        raise ValueError("invalid probe")
    output = {"version": 1, "wrapper": value.get("wrapper") if value.get("wrapper") in {"pass", "fail", "not-run"} else "not-run", "setup": step(value.get("setup")), "enumeration": step(value.get("enumeration")), "nodes": []}
    for node in value.get("nodes", [])[:4]:
        if not isinstance(node, dict) or node.get("role") not in {"directory", "file"} or node.get("setter") not in {"typed", "raw"}:
            continue
        clean = {"role": node["role"], "setter": node["setter"]}
        for key in ["backup_write", "complete_write", "url_write"]: clean[key] = step(node.get(key))
        for key in ["backup_cached", "backup_fresh", "symlink"]: clean[key] = step(node.get(key), "value", {"true", "false", "nil"})
        for key in ["complete_before", "complete_after", "url_before", "url_after", "legacy_after_url"]: clean[key] = protection(node.get(key))
        output["nodes"].append(clean)
    return output


if __name__ == "__main__":
    try:
        lines = Path(sys.argv[1]).read_text(errors="replace").splitlines()
        payload = next(line.split("LOCKLARK_PROTECTION_PROBE ", 1)[1] for line in reversed(lines) if "LOCKLARK_PROTECTION_PROBE " in line)
        print("ios protection metadata " + json.dumps(sanitize(json.loads(payload)), separators=(",", ":")))
    except Exception:
        print("ios protection metadata unavailable")
        sys.exit(1)
