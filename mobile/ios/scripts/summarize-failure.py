#!/usr/bin/env python3
"""Publish fixed diagnostic metadata, never source excerpts or runtime values."""
import json
import re
import sys
from pathlib import Path

KNOWN_SOURCES = {p.name for p in Path(__file__).resolve().parents[1].rglob("*") if p.suffix in {".swift", ".m", ".h"} and "Build" not in p.parts}


def summary(text):
    output = []
    for match in re.finditer(r"(?m)^([^\n:]+\.(?:swift|m|h)):(\d+):\d+:\s*error:\s*([^\n]*)", text):
        name = Path(match[1]).name
        if name not in KNOWN_SOURCES:
            continue
        message = match[3].lower()
        category = next((category for category, needle in [
            ("module-import", "module"), ("missing-symbol", "cannot find"),
            ("missing-member", "has no member"), ("argument-label", "argument"),
            ("actor-isolation", "actor"), ("protocol-conformance", "conform"),
            ("type-conversion", "convert")
        ] if needle in message), "compile")
        output.append({"file": name, "line": int(match[2]), "category": category})
        if len(output) == 12:
            break
    return {"compile_diagnostics": output, "runtime_failed_cases": len(re.findall(r"Test Case .* failed", text))}


if __name__ == "__main__":
    print("ios failure metadata " + json.dumps(summary(Path(sys.argv[1]).read_text(errors="replace")), separators=(",", ":")))
