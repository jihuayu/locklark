#!/usr/bin/env python3
"""Minimal real CLI smoke gate.

This is deliberately smaller than the ``*_acceptance.py`` suites. It proves
that a prebuilt ``locklark`` executable starts, prints its help, creates the
synthetic gateway fixture, and reads two pinned epochs. It uses synthetic data
only and never prints child stdout/stderr, so command output cannot leak into
CI logs during this first gate.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


class SmokeFailure(Exception):
    """A fixed, non-secret smoke failure classification."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def is_executable(path: pathlib.Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def invoke(cli: pathlib.Path, args: list[str], timeout: float) -> bytes:
    try:
        result = subprocess.run(
            [str(cli), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SmokeFailure("CLI invocation failed") from None
    if result.returncode != 0:
        raise SmokeFailure("CLI command failed: " + args[0])
    return result.stdout


def json_output(cli: pathlib.Path, args: list[str], timeout: float) -> dict:
    raw = invoke(cli, args, timeout)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SmokeFailure("CLI returned malformed JSON: " + args[0]) from None
    require(isinstance(value, dict), "CLI returned a non-object JSON value")
    return value


def smoke(cli: pathlib.Path, timeout: float) -> None:
    try:
        help_text = invoke(cli, ["--help"], timeout).decode("utf-8")
    except UnicodeDecodeError:
        raise SmokeFailure("CLI help output is not UTF-8") from None
    require("Locklark" in help_text, "CLI help output is missing the product name")

    state = pathlib.Path(tempfile.mkdtemp(prefix="locklark-cli-smoke-"))
    try:
        state.chmod(0o700)
        demo = json_output(
            cli,
            [
                "demo",
                "--out",
                str(state / "demo"),
                "--session",
                "smoke-1",
                "--reason",
                "synthetic smoke",
            ],
            timeout,
        )
        require(demo.get("synthetic") is True, "demo did not report synthetic data")
        require(demo.get("epochs") == [1, 2, 3], "demo returned unexpected epochs")

        for epoch, device in ((1, "A"), (2, "B")):
            summary = json_output(
                cli,
                [
                    "inspect",
                    "--bundle",
                    str(state / "demo" / "share" / f"epoch-{epoch}"),
                    "--device",
                    str(state / "demo" / "clients" / device),
                    "--epoch",
                    str(epoch),
                ],
                timeout,
            )
            require(
                summary == {"epoch": epoch, "items": 2, "attachments": 1},
                f"synthetic epoch {epoch} summary mismatch",
            )
    finally:
        shutil.rmtree(state, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cli",
        required=True,
        help="path to a prebuilt locklark executable (never rebuilt here)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="per-command timeout in seconds",
    )
    args = parser.parse_args(argv)

    try:
        cli = pathlib.Path(args.cli).expanduser().resolve(strict=True)
        require(is_executable(cli), "CLI path is not an executable file")
        smoke(cli, args.timeout)
    except SmokeFailure as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 1
    except OSError:
        print("FAIL: CLI path is not an executable file", file=sys.stderr)
        return 1

    print("PASS: locklark CLI smoke (help, synthetic demo, pinned inspect)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
