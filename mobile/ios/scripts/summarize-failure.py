#!/usr/bin/env python3
"""Publish fixed diagnostic metadata, never source excerpts or runtime values."""
import argparse
import json
import re
import sys
from pathlib import Path

KNOWN_SOURCES = {p.name for p in Path(__file__).resolve().parents[1].rglob("*") if p.suffix in {".swift", ".m", ".h"} and "Build" not in p.parts}
TESTS = {}
DECLARATIONS = {}
REASONS = set()
PHASES = {"protection-preflight", "capability-denial", "full-positive"}
TERMINAL_MARKERS = {
    "** BUILD FAILED **": "build-failed-marker",
    "** TEST FAILED **": "testing-failed-marker",
    "** TEST SUCCEEDED **": "test-succeeded-marker",
}
DENIAL_CASES = {
    "unit": ("LocklarkCapabilityTests", "ProtectionCapabilityDenialTests", "testUnavailableCompleteProtectionIsRefusedBeforeVaultCreation"),
    "ui": ("LocklarkCapabilityUITests", "ProtectionCapabilityDenialUITests", "testActualAppKeepsCreationDisabledWhenProtectionIsUnavailable"),
}


def process_metadata(text, phase, exit_code):
    # Exit numbers describe the process result, never its underlying cause.
    if type(exit_code) is not int or not 0 <= exit_code <= 255:
        exit_class = "unknown"
    else:
        exit_class = {0: "zero", 65: "exit-65", 70: "exit-70"}.get(exit_code, "other-nonzero")
    terminals = {TERMINAL_MARKERS[line] for line in text.splitlines() if line in TERMINAL_MARKERS}
    terminal = next(iter(terminals)) if len(terminals) == 1 else ("conflicting" if terminals else "unknown")
    denial = {kind: "unknown" for kind in DENIAL_CASES}
    if phase == "capability-denial":
        for kind, (module, name, method) in DENIAL_CASES.items():
            owner = rf"(?:{re.escape(module)}\.)?{re.escape(name)}"
            pattern = rf"^Test Case '-\[{owner} {re.escape(method)}\]' (started\.|(?:passed|failed) \([0-9]+(?:\.[0-9]+)? seconds\)\.)$"
            observed = {match[1].split(" ", 1)[0].rstrip(".") for match in re.finditer(pattern, text, re.MULTILINE)}
            if {"passed", "failed"} <= observed:
                denial[kind] = "conflicting"
            else:
                denial[kind] = next((status for status in ("failed", "passed", "started") if status in observed), "unknown")
    return {"phase": phase if phase in PHASES else "unknown", "exit_class": exit_class, "xcodebuild_terminal": terminal, "denial_tests": denial}


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


def summary(text, phase="unknown", exit_code=None):
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
    return {**process_metadata(text, phase, exit_code), "compile_diagnostics": output, "runtime_diagnostics": runtime[:24], "runtime_failed_cases": len(re.findall(r"Test Case .* failed", text))}


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid diagnostic arguments")


def main(argv):
    try:
        parser = PrivateArgumentParser(description=__doc__)
        parser.add_argument("log", type=Path)
        parser.add_argument("--phase", choices=sorted(PHASES), default="unknown")
        parser.add_argument("--exit-code", type=int)
        args = parser.parse_args(argv)
        if args.exit_code is not None and not 0 <= args.exit_code <= 255:
            raise ValueError("invalid process exit code")
        print("ios failure metadata " + json.dumps(summary(args.log.read_text(errors="replace"), args.phase, args.exit_code), separators=(",", ":")))
        return 0
    except Exception:
        print("ios failure metadata unavailable")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
