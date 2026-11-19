#!/usr/bin/env python3
"""Run the ordered desktop-release security contracts once, fail-closed.

The suite is intentionally one process and one pass over three reviewed
modules:

* scripts/test_authorize_desktop_release.py
* scripts/test_desktop_release_workflow.py
* scripts/test_verify_desktop_release.py

The real Git/GitHub-dispatch routing smoke runs first in the authorization
group. The real Go PE/Mach-O signed-archive smoke runs first in the verifier
group, and the whole verifier class stays contiguous so its class fixtures and
Go build cache are created once per unique target/version.

A missing, empty, duplicated, skipped, expected-failure, unexpected-success,
or errored test is a hard failure. The runner never expands past a skipped
minimum test and never retries or skips a capability silently.
"""

from __future__ import annotations

import importlib
import re
import shutil
import subprocess
import sys
import time
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EXPECTED_GO = "go1.27.3"
EXPECTED_PYYAML = "6.0.3"


class ContractError(RuntimeError):
    """The ordered suite cannot be built or did not satisfy its contract."""


@dataclass(frozen=True)
class Group:
    name: str
    module: str
    test_class: str
    minimum: tuple[str, ...]
    first: str | None = None


@dataclass(frozen=True)
class PlannedTest:
    group: str
    test_id: str
    test: unittest.TestCase


GROUPS: tuple[Group, ...] = (
    Group(
        name="authorize",
        module="scripts.test_authorize_desktop_release",
        test_class="AuthorizationTests",
        minimum=(
            "test_dispatch_real_git_gh_transport_smoke",
            "test_real_lightweight_ancestor_authorizes",
            "test_production_environment_is_default_branch_only",
        ),
        first="test_dispatch_real_git_gh_transport_smoke",
    ),
    Group(
        name="workflow",
        module="scripts.test_desktop_release_workflow",
        test_class="DesktopReleaseWorkflowTests",
        minimum=(
            "test_only_repository_dispatch_trigger_and_no_legacy_workflow",
            "test_authorize_runs_first_with_read_only_permissions",
            "test_all_downstream_jobs_depend_on_authorize",
            "test_primary_build_guard_accepts_current_single_builders",
            "test_primary_build_guard_rejects_duplicate_build_fixtures",
        ),
        first="test_only_repository_dispatch_trigger_and_no_legacy_workflow",
    ),
    Group(
        name="verifier",
        module="scripts.test_verify_desktop_release",
        test_class="VerifyDesktopReleaseTests",
        minimum=(
            # The actual valid signed real-Go archive crypto smoke. It must
            # run before the delta/refusal matrix in the same class.
            "test_valid_release_binds_both_platform_archives",
            "test_00_signed_digest_smoke",
            "test_01_real_signed_delta_smoke",
            "test_actual_bytes_size_and_signature_stay_failclosed",
        ),
        first="test_valid_release_binds_both_platform_archives",
    ),
)


class FailFastResult(unittest.TestResult):
    """Stop after the first failure, error, skip, or expected-failure record."""

    def addFailure(self, test, err):  # type: ignore[no-untyped-def]
        super().addFailure(test, err)
        self.stop()

    def addError(self, test, err):  # type: ignore[no-untyped-def]
        super().addError(test, err)
        self.stop()

    def addSkip(self, test, reason):  # type: ignore[no-untyped-def]
        super().addSkip(test, reason)
        self.stop()

    def addExpectedFailure(self, test, err):  # type: ignore[no-untyped-def]
        super().addExpectedFailure(test, err)
        self.stop()

    def addUnexpectedSuccess(self, test):  # type: ignore[no-untyped-def]
        super().addUnexpectedSuccess(test)
        self.stop()

    def addSubTest(self, test, subtest, err):  # type: ignore[no-untyped-def]
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.stop()


@dataclass
class RunOutcome:
    planned: int
    result: unittest.TestResult
    elapsed: float

    def ok(self) -> bool:
        return (
            self.result.testsRun == self.planned
            and self.result.wasSuccessful()
            and not self.result.skipped
            and not self.result.expectedFailures
            and not self.result.unexpectedSuccesses
            and not self.result.failures
            and not self.result.errors
        )


def _load_module(name: str):
    importlib.invalidate_caches()
    try:
        return importlib.import_module(name)
    except Exception as exc:  # pragma: no cover - exercised by the runner test
        raise ContractError(f"cannot import {name}: {exc}") from exc


def load_plan(groups: tuple[Group, ...] | list[Group]) -> list[PlannedTest]:
    """Load every test method exactly once and enforce the minimum IDs."""

    if not groups:
        raise ContractError("no test groups configured")
    loader = unittest.TestLoader()
    plan: list[PlannedTest] = []
    seen_groups: set[str] = set()
    seen_ids: set[str] = set()
    for group in groups:
        if not group.name or group.name in seen_groups:
            raise ContractError(f"empty or duplicate group name: {group.name!r}")
        seen_groups.add(group.name)
        if not group.minimum:
            raise ContractError(f"{group.name}: minimum test set is empty")
        if group.first is not None and group.first not in group.minimum:
            raise ContractError(f"{group.name}: first test is not in the minimum set")
        module = _load_module(group.module)
        cls = getattr(module, group.test_class, None)
        if not isinstance(cls, type) or not issubclass(cls, unittest.TestCase):
            raise ContractError(
                f"{group.name}: {group.module}.{group.test_class} is not a TestCase"
            )
        names = loader.getTestCaseNames(cls)
        if not names:
            raise ContractError(f"{group.name}: no test methods discovered")
        missing = [name for name in group.minimum if name not in names]
        if missing:
            raise ContractError(f"{group.name}: missing minimum tests: {missing}")
        if group.first is not None and group.first not in names:
            raise ContractError(f"{group.name}: first test {group.first!r} missing")
        ordered = ([group.first] if group.first else []) + [
            name for name in names if name != group.first
        ]
        for name in ordered:
            test_id = f"{group.module}.{cls.__name__}.{name}"
            if test_id in seen_ids:
                raise ContractError(f"duplicate test id: {test_id}")
            seen_ids.add(test_id)
            plan.append(PlannedTest(group.name, test_id, cls(name)))
    if not plan:
        raise ContractError("ordered plan is empty")
    return plan


def run_plan(plan: list[PlannedTest]) -> RunOutcome:
    if not plan:
        raise ContractError("ordered plan is empty")
    suite = unittest.TestSuite(item.test for item in plan)
    result = FailFastResult()
    started = time.monotonic()
    suite.run(result)
    return RunOutcome(len(plan), result, time.monotonic() - started)


def _assert_runtime() -> None:
    if shutil.which("git") is None:
        raise ContractError("git is required for the real dispatch contracts")
    if shutil.which("go") is None:
        raise ContractError("go is required for the synthetic archive fixtures")
    if shutil.which("openssl") is None:
        raise ContractError("openssl is required for the signed archive fixtures")
    try:
        import yaml  # noqa: F401
    except Exception as exc:  # pragma: no cover - CI installs it explicitly
        raise ContractError("PyYAML is required for workflow contracts") from exc
    if yaml.__version__ != EXPECTED_PYYAML:
        raise ContractError(
            f"PyYAML {EXPECTED_PYYAML} required, found {yaml.__version__!r}"
        )
    go_version = subprocess.run(
        ["go", "env", "GOVERSION"],
        capture_output=True,
        text=True,
        check=False,
    )
    if go_version.returncode != 0:
        raise ContractError("cannot query the Go toolchain version")
    if go_version.stdout.strip() != EXPECTED_GO:
        raise ContractError(
            f"{EXPECTED_GO} required, found {go_version.stdout.strip()!r}"
        )
    openssl_version = subprocess.run(
        ["openssl", "version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if openssl_version.returncode != 0 or not re.search(r"OpenSSL \S+", openssl_version.stdout):
        raise ContractError("openssl is not usable")


def _print_problems(result: unittest.TestResult) -> None:
    for label, entries in (
        ("FAIL", result.failures),
        ("ERROR", result.errors),
        ("SKIP", result.skipped),
        ("EXPECTED-FAILURE", result.expectedFailures),
        ("UNEXPECTED-SUCCESS", result.unexpectedSuccesses),
    ):
        for test, detail in entries:
            print(f"{label}: {test.id()}", file=sys.stderr)
            if detail:
                print(str(detail).rstrip(), file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    del argv
    try:
        _assert_runtime()
        plan = load_plan(GROUPS)
    except ContractError as exc:
        print(f"release contracts: FAIL: {exc}", file=sys.stderr)
        return 2
    counts: dict[str, int] = {}
    for item in plan:
        counts[item.group] = counts.get(item.group, 0) + 1
    print(
        "release contracts: "
        + ", ".join(f"{group.name}={counts.get(group.name, 0)}" for group in GROUPS)
        + f" ({len(plan)} tests)"
    )
    outcome = run_plan(plan)
    if not outcome.ok():
        _print_problems(outcome.result)
        print(
            f"release contracts: FAIL after {outcome.result.testsRun}/{outcome.planned} "
            f"tests in {outcome.elapsed:.2f}s",
            file=sys.stderr,
        )
        return 1
    print(
        f"release contracts: OK {outcome.result.testsRun}/{outcome.planned} "
        f"tests in {outcome.elapsed:.2f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
