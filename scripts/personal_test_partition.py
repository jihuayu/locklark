#!/usr/bin/env python3
"""Run the personal Go package in two bounded, disjoint test-binary groups.

On Windows the whole `internal/personal` package now approaches Go's default
10 minute test timeout. This runner compiles its test binary exactly once,
lists every default top-level Test/Example/Fuzz case, splits that list into two
balanced nonempty groups, and runs each group exactly once through the same
binary with an explicit 10 minute cap. Every other package is still run by a
single `go test -count=1` invocation that excludes only the exact personal
package. Groups run sequentially so the split does not add CPU or memory
contention.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

PERSONAL_PACKAGE = "github.com/jihuayu/locklark/internal/personal"
GROUP_TIMEOUT = "10m"
TOP_LEVEL_CASE = re.compile(r"^(?:Test|Example|Fuzz)[A-Za-z0-9_]*$")


class PartitionError(RuntimeError):
    """A malformed package list, test list, partition, or failed group."""


def validate_cases(cases: list[str]) -> list[str]:
    """Return the cases unchanged after rejecting empty/malformed/duplicate data."""
    if not isinstance(cases, (list, tuple)) or not cases:
        raise PartitionError("personal top-level test list is empty")
    seen: set[str] = set()
    validated: list[str] = []
    for case in cases:
        if not isinstance(case, str) or not TOP_LEVEL_CASE.fullmatch(case):
            raise PartitionError("personal top-level test list is malformed")
        if case in seen:
            raise PartitionError("personal top-level test list contains a duplicate")
        seen.add(case)
        validated.append(case)
    return validated


def validate_partition(cases: list[str], groups: tuple[list[str], list[str]]) -> None:
    """Prove both groups are nonempty, disjoint, balanced and cover every case."""
    ordered = sorted(validate_cases(cases))
    if not isinstance(groups, (list, tuple)) or len(groups) != 2:
        raise PartitionError("personal partition must have exactly two groups")
    flattened: list[str] = []
    for group in groups:
        if not isinstance(group, (list, tuple)) or not group:
            raise PartitionError("personal partition group is empty")
        # Reuse the top-level shape check, then prove global disjointness below.
        for case in group:
            if not isinstance(case, str) or not TOP_LEVEL_CASE.fullmatch(case):
                raise PartitionError("personal partition group is malformed")
            flattened.append(case)
    if len(set(flattened)) != len(flattened):
        raise PartitionError("personal partition groups overlap or repeat a case")
    if set(flattened) != set(ordered):
        raise PartitionError("personal partition has a gap or an unknown case")
    if abs(len(groups[0]) - len(groups[1])) > 1:
        raise PartitionError("personal partition groups are not balanced")


def partition_cases(cases: list[str]) -> tuple[list[str], list[str]]:
    """Split the sorted top-level cases alternately into two balanced groups."""
    ordered = sorted(validate_cases(cases))
    if len(ordered) < 2:
        raise PartitionError("personal test list cannot make two nonempty groups")
    first = ordered[0::2]
    second = ordered[1::2]
    groups = (first, second)
    validate_partition(ordered, groups)
    return groups


def filter_other_packages(packages: list[str]) -> list[str]:
    """Exclude exactly the personal package, never a similarly named one."""
    if not isinstance(packages, (list, tuple)) or not packages:
        raise PartitionError("Go package list is empty")
    seen: set[str] = set()
    for package in packages:
        if not isinstance(package, str) or not package or package.strip() != package:
            raise PartitionError("Go package list is malformed")
        if package in seen:
            raise PartitionError("Go package list contains a duplicate")
        seen.add(package)
    if PERSONAL_PACKAGE not in seen:
        raise PartitionError("personal package is missing from the Go package list")
    others = [package for package in packages if package != PERSONAL_PACKAGE]
    if not others:
        raise PartitionError("no non-personal Go packages remain")
    return others


def _go(env: dict[str, str] | None = None) -> str:
    executable = shutil.which("go", path=(env or os.environ).get("PATH"))
    if executable is None:
        raise PartitionError("go executable is unavailable")
    return executable


def _run(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: pathlib.Path | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=capture,
    )


def list_packages(env: dict[str, str] | None = None) -> list[str]:
    result = _run([_go(env), "list", "./..."], env=env, capture=True)
    if result.returncode != 0:
        detail = (result.stderr or "").strip()
        raise PartitionError(f"go list failed with exit {result.returncode}: {detail}")
    packages = result.stdout.splitlines()
    if not packages:
        raise PartitionError("go list returned no packages")
    if len(set(packages)) != len(packages):
        raise PartitionError("go list contains a duplicate package")
    if any(not package or package.strip() != package for package in packages):
        raise PartitionError("go list contains a malformed package")
    return packages


def package_directory(package: str, env: dict[str, str] | None = None) -> pathlib.Path:
    result = _run([_go(env), "list", "-f", "{{.Dir}}", package], env=env, capture=True)
    if result.returncode != 0:
        detail = (result.stderr or "").strip()
        raise PartitionError(f"go list package directory failed with exit {result.returncode}: {detail}")
    directory = pathlib.Path(result.stdout.strip())
    if not directory.is_absolute() or not directory.is_dir():
        raise PartitionError("personal package directory is not an absolute directory")
    return directory


def run_other_packages(packages: list[str], env: dict[str, str] | None = None) -> int:
    others = filter_other_packages(packages)
    print(f"go: running {len(others)} non-personal packages exactly once with -count=1", flush=True)
    return _run([_go(env), "test", "-count=1", *others], env=env).returncode


def compile_test_binary(package: str, output: pathlib.Path, env: dict[str, str] | None = None) -> None:
    print("personal: compiling the test binary once", flush=True)
    result = _run([_go(env), "test", "-c", "-o", str(output), package], env=env)
    if result.returncode != 0:
        raise PartitionError(f"personal test binary compilation failed with exit {result.returncode}")


def list_test_cases(binary: str, env: dict[str, str] | None = None) -> list[str]:
    # The test binary also lists benchmarks, so select exactly the default
    # top-level Test/Example/Fuzz names. No benchmark flag is ever supplied.
    result = _run([binary, "-test.list", "^(Test|Example|Fuzz)"], env=env, capture=True)
    if result.returncode != 0:
        detail = (result.stderr or "").strip()
        raise PartitionError(f"personal test list failed with exit {result.returncode}: {detail}")
    cases = result.stdout.splitlines()
    return sorted(validate_cases(cases))


def run_group(
    binary: str,
    cases: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: pathlib.Path | None = None,
    timeout: str = GROUP_TIMEOUT,
) -> int:
    selected = validate_cases(cases)
    if not selected:
        raise PartitionError("personal group is empty")
    pattern = "^(?:" + "|".join(re.escape(case) for case in selected) + ")$"
    # -test.paniconexit0 and -test.timeout mirror the flags `go test` supplies,
    # so a test exiting zero cannot be mistaken for a pass and the cap is the
    # same default 10m rather than a relaxed one.
    command = [
        binary,
        "-test.run",
        pattern,
        "-test.count=1",
        "-test.paniconexit0",
        f"-test.timeout={timeout}",
    ]
    return _run(command, env=env, cwd=cwd).returncode


def run_partitioned(
    binary: str,
    cases: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: pathlib.Path | None = None,
    timeout: str = GROUP_TIMEOUT,
) -> tuple[list[str], list[str]]:
    groups = partition_cases(cases)
    codes: list[int] = []
    for index, group in enumerate(groups, start=1):
        print(f"personal: running group {index}/2 ({len(group)} cases)", flush=True)
        codes.append(run_group(binary, group, env=env, cwd=cwd, timeout=timeout))
    if any(codes):
        raise PartitionError("one or more personal test groups failed")
    return groups


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--personal-package", default=PERSONAL_PACKAGE)
    parser.add_argument("--timeout", default=GROUP_TIMEOUT)
    args = parser.parse_args(argv)
    if args.personal_package != PERSONAL_PACKAGE:
        parser.error("only the exact personal package can be split")
    if args.timeout != GROUP_TIMEOUT:
        parser.error("the personal group cap must remain 10m")
    try:
        packages = list_packages()
        other_code = run_other_packages(packages)
        package_dir = package_directory(PERSONAL_PACKAGE)
        with tempfile.TemporaryDirectory(prefix="locklark-personal-test-") as temporary:
            name = "personal.test.exe" if os.name == "nt" else "personal.test"
            binary = pathlib.Path(temporary) / name
            compile_test_binary(PERSONAL_PACKAGE, binary)
            cases = list_test_cases(str(binary))
            groups = partition_cases(cases)
            print(
                f"personal: {len(cases)} top-level cases in two groups "
                f"({len(groups[0])}/{len(groups[1])})",
                flush=True,
            )
            try:
                run_partitioned(str(binary), cases, cwd=package_dir)
            except PartitionError:
                if other_code != 0:
                    print("go: non-personal packages also failed", file=sys.stderr, flush=True)
                raise
        if other_code != 0:
            print(f"go: non-personal packages failed with exit {other_code}", file=sys.stderr, flush=True)
            return other_code
        return 0
    except PartitionError as error:
        print(f"personal partition runner: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
