#!/usr/bin/env python3
"""Publish fixed diagnostic metadata, never source excerpts or runtime values."""
import json
import re
import sys
from pathlib import Path

KNOWN_SOURCES = {p.name for p in Path(__file__).resolve().parents[1].rglob("*") if p.suffix in {".swift", ".m", ".h"} and "Build" not in p.parts}
TESTS = {}
DECLARATIONS = {}
REASONS = set()


def fixed_reasons(source):
    reasons = {"native control must be actionable"}
    literals = re.findall(r'XCT(?:Assert\w*|Fail)\([^\n]*"([^"\n]*)"\s*\)', source)
    literals += re.findall(r'\b(?:waitActionable|tapActionable)\([^\n;]*\bmessage:\s*"([^"\n]*)"', source)
    for reason in literals:
        if "\\(" not in reason and 0 < len(reason) <= 180:
            reasons.add(reason)
    reasons.update(re.findall(r'case\s+\w+\s*=\s*"(core-phase-[a-z-]+)"', source))
    return reasons


for path in Path(__file__).resolve().parents[1].rglob("*.swift"):
    if "Build" in path.parts or "Tests" not in str(path.parent):
        continue
    source = path.read_text()
    classes = [name for name in re.findall(r"\bclass\s+(\w+)", source) if name.endswith("Tests")]
    methods = re.findall(r"\bfunc\s+(test\w+)\s*\(", source)
    TESTS[path.name] = {(name, method) for name in classes for method in methods}
    for match in re.finditer(r"\bfunc\s+(test\w+)\s*\(", source):
        for name in classes:
            DECLARATIONS[(name, match[1])] = (path.name, source[:match.start()].count("\n") + 1)
    REASONS.update(fixed_reasons(source))


def summary(text):
    output = []
    for match in re.finditer(r"(?m)^([^\n:]+\.(?:swift|m|h)):(\d+):\d+:\s*error:\s*([^\n]*)", text):
        name = Path(match[1]).name
        if name not in KNOWN_SOURCES:
            continue
        message = match[3].lower()
        if "xctassert" in message or re.search(r"-\[[^]]+ test\w+\]", match[3]):
            continue
        category = next((category for category, needle in [
            ("module-import", "module"), ("missing-symbol", "cannot find"),
            ("missing-member", "has no member"), ("argument-label", "argument"),
            ("actor-isolation", "actor"), ("protocol-conformance", "conform"),
            ("type-conversion", "convert")
        ] if needle in message), "compile")
        output.append({"file": name, "line": int(match[2]), "category": category})
        if len(output) == 12:
            break
    runtime = []
    for match in re.finditer(r"(?m)^.*?([A-Za-z][A-Za-z0-9_]*\.swift):(\d+):(?:\d+:)?\s*(?:error:\s*)?([^\n]*)", text):
        filename, line, message = match.groups()
        if filename not in TESTS:
            continue
        pairs = re.findall(r"-\[([A-Za-z0-9_.]+)\s+(test\w+)\]", message)
        pairs += re.findall(r"\b([A-Za-z0-9_]+)\.(test\w+)\(", message)
        allowed = next(((name.split(".")[-1], method) for name, method in pairs if (name.split(".")[-1], method) in TESTS[filename]), None)
        if allowed is None:
            continue
        reason = next((reason for reason in sorted(REASONS, key=len, reverse=True) if reason in message), None)
        runtime.append({"file": filename, "line": int(line), "case": ".".join(allowed), "reason": reason or ("assertion" if "XCTAssert" in message else "unexpected-error")})
        if len(runtime) == 24:
            break
    seen = {item["case"] for item in runtime}
    for line in text.splitlines():
        if "error:" not in line:
            continue
        for name, method in re.findall(r"-\[([A-Za-z0-9_.]+)\s+(test\w+)\]", line):
            pair = (name.split(".")[-1], method)
            case = ".".join(pair)
            if pair in DECLARATIONS and case not in seen:
                filename, declared = DECLARATIONS[pair]
                runtime.append({"file": filename, "line": declared, "location": "method-declaration", "case": case, "reason": "unexpected-error"})
                seen.add(case)
    return {"compile_diagnostics": output, "runtime_diagnostics": runtime[:24], "runtime_failed_cases": len(re.findall(r"Test Case .* failed", text))}


if __name__ == "__main__":
    print("ios failure metadata " + json.dumps(summary(Path(sys.argv[1]).read_text(errors="replace")), separators=(",", ":")))
