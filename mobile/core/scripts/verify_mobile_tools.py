#!/usr/bin/env python3
"""Verify installed gomobile/go bind tools match the pinned x/mobile module."""
import argparse
import os
import subprocess
import sys

MOBILE_VERSION = "v0.0.0-20260908204917-8b95e45f8d3e"
MOBILE_SUM = "h1:zYnHsDmxfxKH/x9DjYNAdoIdMsP8enB1Ncb10b3pdHk="


def metadata_matches(text):
    version = sum_value = None
    for line in text.splitlines():
        fields = line.replace("\t", " ").split()
        if len(fields) >= 4 and fields[0] == "mod" and fields[1] == "golang.org/x/mobile":
            version, sum_value = fields[2], fields[3]
            break
    return version == MOBILE_VERSION and sum_value == MOBILE_SUM


def verify_metadata(outputs):
    return bool(outputs) and all(metadata_matches(output) for output in outputs)


def tool_output(go_bin, path):
    if not path or not os.path.isfile(path) or not os.access(path, os.X_OK):
        return None
    try:
        completed = subprocess.run(
            [go_bin, "version", "-m", path],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def verify_tools(go_bin, paths):
    outputs = []
    for path in paths:
        output = tool_output(go_bin, path)
        if output is None:
            return False
        outputs.append(output)
    return verify_metadata(outputs)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go", help="Go executable")
    parser.add_argument("tools", nargs="+", help="built gomobile/go bind tools")
    args = parser.parse_args(argv)
    if not verify_tools(args.go, args.tools):
        print("verify-mobile-tools: failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
