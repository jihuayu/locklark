"""Command line entry point for preparation and verification."""

from __future__ import annotations

import argparse
import json
import sys

from . import allowlist, package
from .errors import ReleaseError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare or verify deterministic unsigned browser-extension ZIPs from "
            "the real build output. This never signs, publishes or uploads anything."
        )
    )
    parser.add_argument("--product", required=True, choices=allowlist.PRODUCTS)
    parser.add_argument("--output", required=True, help="absolute output directory")
    parser.add_argument("--verify", action="store_true", help="verify only")
    args = parser.parse_args(argv)
    try:
        summary = (
            package.verify(args.product, args.output)
            if args.verify
            else package.prepare(args.product, args.output)
        )
    except ReleaseError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "PASS: verified unsigned preparation"
        if args.verify
        else "PASS: prepared unsigned artifact"
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
