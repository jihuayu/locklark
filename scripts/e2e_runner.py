#!/usr/bin/env python3
"""Unified opaque-box E2E runner for the Locklark M5 test track.

The runner imports test modules from ``tests/e2e`` lazily, executes every
selected test in its own :class:`~tests.e2e.harness.E2EContext`, and reports a
structured PASS / PENDING_FEATURE / FAIL summary.

It is intentionally usable before the milestone test modules land: missing
canonical modules are ignored, while a module that exists but fails to import
is reported as a hard error.
"""

from __future__ import annotations

import argparse
import importlib
import io
import json
import os
import re
import struct
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.e2e.harness import (  # noqa: E402  (path setup must run first)
    COVERAGE_KINDS,
    E2EContext,
    FIREFOX_EXT_ID,
    FeatureNotImplementedError,
    SECRET_KEY_RE,
    VALID_FEATURES,
    VALID_TIERS,
    _go_build_targets,
    ensure_binaries_built,
    ensure_vm_temp_root,
    get_registered_tests,
)

# Set the VM recipe before discovery/builds/subprocesses.
ensure_vm_temp_root()

CANONICAL_TEST_MODULES = (
    "tier1_f01_f08",
    "tier2_f01_f08",
    "tier1_f09_f17",
    "tier2_f09_f17",
    "tier3_pairwise",
    "tier4_scenarios",
)

STATUS_PASS = "PASS"
STATUS_PENDING = "PENDING_FEATURE"
STATUS_FAIL = "FAIL"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _import_optional_module(name: str, attempted: set[str]) -> None:
    """Import a suite module; ignore only a genuinely absent canonical file."""

    if name in attempted:
        return
    full_name = f"tests.e2e.{name}"
    if full_name in sys.modules:
        attempted.add(name)
        return
    try:
        importlib.import_module(full_name)
    except ModuleNotFoundError as exc:
        if exc.name == full_name:
            attempted.add(name)
            return
        raise RuntimeError(
            f"Failed to import {full_name}: missing dependency {exc.name!r}"
        ) from exc
    except Exception as exc:  # syntax errors, bad imports, registration bugs
        raise RuntimeError(
            f"Failed to import {full_name}: {type(exc).__name__}: {exc}"
        ) from exc
    attempted.add(name)


def discover_test_modules() -> list[str]:
    """Import the canonical modules and any other ``tests/e2e/tier*.py``."""

    attempted: set[str] = set()
    imported: list[str] = []
    for name in CANONICAL_TEST_MODULES:
        before = name in sys.modules
        _import_optional_module(name, attempted)
        if name in sys.modules and not before:
            imported.append(name)

    test_dir = REPO_ROOT / "tests" / "e2e"
    if test_dir.is_dir():
        for path in sorted(test_dir.glob("tier*.py")):
            name = path.stem
            if name == "__init__" or name in attempted:
                continue
            before = name in sys.modules
            _import_optional_module(name, attempted)
            if name in sys.modules and not before:
                imported.append(name)
    return imported


# ---------------------------------------------------------------------------
# Filtering / counts
# ---------------------------------------------------------------------------


def _parse_feature_filter(
    parser: argparse.ArgumentParser, raw: list[str]
) -> tuple[bool, list[str]]:
    all_requested = False
    selected: list[str] = []
    for entry in raw:
        for token in entry.split(","):
            token = token.strip()
            if not token:
                parser.error("--feature requires F1..F17, comma-separated values, or 'all'")
            if token.lower() == "all":
                all_requested = True
                continue
            normalized = token.upper()
            if normalized not in VALID_FEATURES:
                parser.error(
                    f"invalid feature {token!r}; expected F1..F17 or 'all'"
                )
            if normalized not in selected:
                selected.append(normalized)
    return all_requested, selected


def select_tests(
    tier: str,
    all_features: bool,
    feature_filter: list[str],
    id_filter: str | None,
) -> list[Any]:
    selected = []
    wanted_tier = None if tier == "all" else int(tier)
    wanted_features = set(feature_filter) if not all_features else set()
    for spec in get_registered_tests():
        if wanted_tier is not None and spec.tier != wanted_tier:
            continue
        if wanted_features and not wanted_features.intersection(spec.features):
            continue
        if id_filter is not None and id_filter not in spec.test_id:
            continue
        selected.append(spec)
    selected.sort(key=lambda spec: (spec.tier, spec.test_id))
    return selected


def _empty_counts() -> dict[str, int]:
    return {"total": 0, "pass": 0, "pending_feature": 0, "fail": 0}


def _count_status(counts: dict[str, int], status: str) -> None:
    counts["total"] += 1
    if status == STATUS_PASS:
        counts["pass"] += 1
    elif status == STATUS_PENDING:
        counts["pending_feature"] += 1
    else:
        counts["fail"] += 1


def _print_list(specs: list[Any]) -> None:
    header = ("TEST_ID", "TIER", "FEATURES", "SUMMARY")
    rows: list[tuple[str, str, str, str]] = [
        (spec.test_id, str(spec.tier), ",".join(spec.features), spec.summary)
        for spec in specs
    ]
    widths = [
        max(len(header[column]), *(len(row[column]) for row in rows))
        if rows
        else len(header[column])
        for column in range(4)
    ]
    print(
        f"{header[0]:<{widths[0]}}  {header[1]:<{widths[1]}}  "
        f"{header[2]:<{widths[2]}}  {header[3]}"
    )
    print(
        f"{'-' * widths[0]}  {'-' * widths[1]}  "
        f"{'-' * widths[2]}  {'-' * widths[3]}"
    )
    for test_id, tier, features, summary in rows:
        print(
            f"{test_id:<{widths[0]}}  {tier:<{widths[1]}}  "
            f"{features:<{widths[2]}}  {summary}"
        )
    print()
    print(f"Matching tests: {len(specs)}")
    print()
    print("Registration counts by tier (all registered tests):")
    for tier in VALID_TIERS:
        count = sum(1 for spec in get_registered_tests() if spec.tier == tier)
        print(f"  Tier {tier}: {count}")
    print()
    print("Registration counts by feature (all registered tests):")
    for feature in VALID_FEATURES:
        count = sum(
            1 for spec in get_registered_tests() if feature in spec.features
        )
        print(f"  {feature}: {count}")


# ---------------------------------------------------------------------------
# Execution / reporting
# ---------------------------------------------------------------------------


def _classify_exception(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, FeatureNotImplementedError):
        return STATUS_PENDING, str(exc)
    if isinstance(exc, AssertionError):
        return STATUS_FAIL, str(exc) or "assertion failed"
    return STATUS_FAIL, f"{type(exc).__name__}: {exc}"


def run_tests(specs: list[Any], bin_dir: Path, start_all: float) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    by_tier = {str(tier): _empty_counts() for tier in VALID_TIERS}
    by_feature = {feature: _empty_counts() for feature in VALID_FEATURES}
    by_coverage = {kind: _empty_counts() for kind in COVERAGE_KINDS}

    for spec in specs:
        start = time.monotonic()
        ctx: E2EContext | None = None
        status = STATUS_PASS
        message = ""
        try:
            ctx = E2EContext(
                repo_root=REPO_ROOT, bin_dir=bin_dir, test_id=spec.test_id
            )
            spec.func(ctx)
        except FeatureNotImplementedError as exc:
            status, message = _classify_exception(exc)
        except Exception as exc:  # noqa: BLE001 - runner must record every test
            status, message = _classify_exception(exc)
            traceback.print_exc(file=sys.stderr)
        finally:
            end = time.monotonic()
            if ctx is not None:
                ctx.cleanup()
        duration = max(0.0, end - start)

        record = {
            "test_id": spec.test_id,
            "tier": spec.tier,
            "features": list(spec.features),
            "summary": spec.summary,
            "coverage_kind": spec.coverage_kind,
            "status": status,
            "duration_sec": round(duration, 6),
            "message": message,
        }
        if ctx is not None and ctx.evidence is not None:
            record["evidence"] = ctx.evidence
        results.append(record)
        _count_status(by_tier[str(spec.tier)], status)
        for feature in spec.features:
            _count_status(by_feature[feature], status)
        _count_status(by_coverage[spec.coverage_kind], status)

        print(
            f"[{status}] {spec.test_id} "
            f"(Tier {spec.tier}, {spec.coverage_kind}, {', '.join(spec.features)}) "
            f"[{int(duration * 1000)}ms]",
            flush=True,
        )

    total = len(results)
    pass_count = sum(1 for item in results if item["status"] == STATUS_PASS)
    pending_count = sum(
        1 for item in results if item["status"] == STATUS_PENDING
    )
    fail_count = sum(1 for item in results if item["status"] == STATUS_FAIL)

    return {
        "summary": {
            "total": total,
            "pass": pass_count,
            "pending_feature": pending_count,
            "fail": fail_count,
            "strict": False,  # filled by main once args are known
            "duration_sec": round(max(0.0, time.monotonic() - start_all), 6),
        },
        "by_tier": by_tier,
        "by_feature": by_feature,
        "by_coverage": by_coverage,
        "results": results,
    }


def _print_summary(report: dict[str, Any], strict: bool) -> None:
    summary = report["summary"]
    print()
    print("=" * 72)
    print("Locklark M5 E2E summary")
    print("=" * 72)
    print(
        f"Total: {summary['total']}  "
        f"PASS: {summary['pass']}  "
        f"PENDING_FEATURE: {summary['pending_feature']}  "
        f"FAIL: {summary['fail']}"
    )
    print(f"Strict mode: {'yes' if strict else 'no'}")
    print()
    print("By tier:")
    for tier in VALID_TIERS:
        counts = report["by_tier"][str(tier)]
        print(
            f"  Tier {tier}: total={counts['total']} "
            f"pass={counts['pass']} "
            f"pending_feature={counts['pending_feature']} "
            f"fail={counts['fail']}"
        )
    print()
    print("By coverage kind:")
    for kind in COVERAGE_KINDS:
        counts = report["by_coverage"][kind]
        print(
            f"  {kind}: total={counts['total']} "
            f"pass={counts['pass']} "
            f"pending_feature={counts['pending_feature']} "
            f"fail={counts['fail']}"
        )
    print("Note: capability_probe PASS means the declared capability surface was probed;")
    print("it does not close the unverified end-to-end user journey.")
    print()
    print("By feature:")
    for feature in VALID_FEATURES:
        counts = report["by_feature"][feature]
        print(
            f"  {feature}: total={counts['total']} "
            f"pass={counts['pass']} "
            f"pending_feature={counts['pending_feature']} "
            f"fail={counts['fail']}"
        )
    print("=" * 72)


def _write_json_report(path: str, report: dict[str, Any]) -> None:
    target = Path(path)
    if target.parent and str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Built-in self-test
# ---------------------------------------------------------------------------


def _run_self_test(bin_dir: Path) -> int:
    checks: list[str] = []

    def check(name: str, fn: Callable[[], None]) -> None:
        started = time.monotonic()
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - report the exact check
            print(
                f"[self-test] FAIL {name}: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            traceback.print_exc(file=sys.stderr)
            raise
        elapsed = int((time.monotonic() - started) * 1000)
        checks.append(name)
        print(f"[self-test] PASS {name} [{elapsed}ms]", flush=True)

    root = ensure_vm_temp_root()

    def check_environment() -> None:
        assert root.is_dir(), f"temporary root is missing: {root}"
        assert (
            root.stat().st_mode & 0o777
        ) == 0o700, f"temporary root is not 0700: {oct(root.stat().st_mode)}"
        assert os.environ.get("TMPDIR") == str(root), (
            f"TMPDIR={os.environ.get('TMPDIR')!r} does not match {root}"
        )
        assert "GOPROXY" in os.environ, "GOPROXY was not initialized"
        for path in (
            bin_dir / "locklark",
            bin_dir / "locklark-browser-chromium",
            bin_dir / "locklark-browser-firefox",
            bin_dir / "locklark-browser-register",
            bin_dir / "locklark-desktop",
        ):
            assert path.is_file() and os.access(path, os.X_OK), (
                f"required binary is missing or not executable: {path}"
            )

    check("environment and compiled binaries", check_environment)

    ctx = E2EContext(repo_root=REPO_ROOT, bin_dir=bin_dir, test_id="self-test")
    state: dict[str, Any] = {}
    try:

        def check_context() -> None:
            assert ctx.temp_dir.is_dir()
            assert (ctx.temp_dir.stat().st_mode & 0o777) == 0o700
            assert ctx.temp_dir.parent.name == "e2e-runs"
            assert ctx.locklark_bin.is_file()
            assert ctx.browser_chromium_bin.is_file()
            assert ctx.browser_firefox_bin.is_file()
            assert ctx.browser_register_bin.is_file()
            assert ctx.desktop_bin.is_file()
            assert ctx.team_sync_bin is None or os.access(
                ctx.team_sync_bin, os.X_OK
            )

        check("E2EContext isolation and paths", check_context)

        def check_run_cli() -> None:
            result = ctx.run_cli(["help"])
            assert result.returncode == 0, result.stderr
            assert "Locklark" in result.stdout
            assert result.args[0] == str(ctx.locklark_bin)
            assert result["returncode"] == 0

        check("run_cli against the real CLI", check_run_cli)

        def check_run_node() -> None:
            result = ctx.run_node(
                "process.stdout.write(process.env.TMPDIR || '')"
            )
            assert result.returncode == 0, result.stderr
            assert Path(result.stdout.strip()) == ctx.temp_dir, result.stdout

        check("run_node with isolated TMPDIR", check_run_node)

        def check_init_vault() -> None:
            vault, password, secret = ctx.init_vault()
            assert vault.is_file()
            assert (vault.stat().st_mode & 0o077) == 0, (
                f"vault permissions are too broad: {oct(vault.stat().st_mode)}"
            )
            assert SECRET_KEY_RE.fullmatch(secret.encode("ascii")), secret
            raw = vault.read_bytes()
            assert password.encode("utf-8") not in raw
            assert secret.encode("ascii") not in raw
            state.update(vault=vault, password=password, secret=secret)

        check("init_vault through real PTY prompts", check_init_vault)

        def check_add_login() -> None:
            item_id, revision = ctx.add_login(
                state["vault"],
                state["password"],
                state["secret"],
                "M5 self-test login",
                "m5-self-test-user",
                "m5-self-test-password-2026",
            )
            assert item_id and item_id.strip()
            assert re.fullmatch(r"[a-f0-9]{64}", revision), revision
            state.update(item_id=item_id, revision=revision)

        check("add_login and revision lookup", check_add_login)

        def check_pty_roundtrip() -> None:
            result = ctx.run_pty_cli(
                ["personal", "list", "--file", str(state["vault"])],
                prompts=[
                    ("主密码", state["password"]),
                    ("Secret Key", state["secret"]),
                ],
            )
            assert result.returncode == 0, result.transcript
            rows = result.json()
            assert isinstance(rows, list)
            assert any(
                row.get("id") == state["item_id"]
                and row.get("revision") == state["revision"]
                for row in rows
            ), rows
            assert result.echo_restored, "terminal echo was not restored"
            assert state["password"] not in result.transcript
            assert state["secret"] not in result.transcript
            assert state["secret"] not in result.stdout

        check("run_pty_cli hidden prompts and echo restoration", check_pty_roundtrip)

        def check_framing() -> None:
            payload = {"v": 1, "id": "a" * 32, "type": "hello"}
            raw = ctx.encode_native_frame(payload)
            (length,) = struct.unpack("=I", raw[:4])
            assert length == len(raw) - 4
            assert ctx.read_native_frame(io.BytesIO(raw)) == payload
            json_body = json.dumps(payload, separators=(",", ":")).encode()
            assert raw == struct.pack("=I", len(json_body)) + json_body

        check("native messaging framing", check_framing)

        def check_native_host() -> None:
            request = {
                "v": 1,
                "id": "a" * 32,
                "type": "cancel",
                "capability": "b" * 32,
            }
            probe = ctx.probe_native_host_frame(
                ctx.encode_native_frame(request), timeout=20.0
            )
            assert not probe.timed_out, probe.stderr
            assert probe.returncode == 0, probe.stderr
            assert probe.frames, (
                "native host returned no frames; stderr=" + probe.stderr
            )
            assert any(
                frame.get("type") == "error"
                and frame.get("id") == request["id"]
                for frame in probe.frames
            ), probe.frames
            first = ctx.read_native_frame(io.BytesIO(probe.raw_stdout))
            assert first == probe.frames[0]

        check("probe_native_host_frame via real native host", check_native_host)

        def check_extension() -> None:
            chromium, firefox = ctx.ensure_extension_built()
            assert chromium.is_dir() and firefox.is_dir()
            for directory in (chromium, firefox):
                manifest = json.loads(
                    (directory / "manifest.json").read_text(encoding="utf-8")
                )
                assert (directory / "background.js").is_file()
                assert (directory / "popup.html").is_file()
                assert manifest["manifest_version"] == 3
            chromium_manifest = json.loads(
                (chromium / "manifest.json").read_text(encoding="utf-8")
            )
            firefox_manifest = json.loads(
                (firefox / "manifest.json").read_text(encoding="utf-8")
            )
            assert (
                chromium_manifest["background"]["service_worker"]
                == "background.js"
            )
            assert (
                firefox_manifest["browser_specific_settings"]["gecko"]["id"]
                == FIREFOX_EXT_ID
            )
            assert ctx.ensure_extension_built() == (chromium, firefox)

        check("ensure_extension_built for Chromium and Firefox", check_extension)

        def check_canary() -> None:
            ctx.assert_no_canary_leak(
                "canary-not-present",
                "ordinary text",
                b"ordinary bytes",
                Path("/tmp/example"),
                {"nested": ["values"]},
            )
            try:
                ctx.assert_no_canary_leak(
                    "leaked-canary", {"nested": ["leaked-canary"]}
                )
            except AssertionError as exc:
                assert "leaked in output #0" in str(exc), exc
            else:
                raise AssertionError("canary leak was not detected")
            try:
                ctx.assert_no_canary_leak("", "text")
            except AssertionError:
                pass
            else:
                raise AssertionError("empty canary was accepted")

        check("assert_no_canary_leak", check_canary)

        def check_require_feature() -> None:
            try:
                ctx.require_feature("F17", False, "desktop CLI broker absent")
            except FeatureNotImplementedError as exc:
                expected = (
                    "[PROGRESSIVE_UNIMPLEMENTED: F17] desktop CLI broker absent"
                )
                assert str(exc) == expected, str(exc)
            else:
                raise AssertionError("require_feature did not gate F17")
            ctx.require_feature("F17", True, "desktop CLI broker present")

        check("require_feature progressive gate", check_require_feature)

        temp_dir = ctx.temp_dir

        def check_cleanup() -> None:
            ctx.cleanup()
            assert not temp_dir.exists(), f"temporary directory survived: {temp_dir}"
            ctx.cleanup()

        check("E2EContext cleanup is idempotent", check_cleanup)
    finally:
        ctx.cleanup()

    print()
    print(f"SELF-TEST PASSED ({len(checks)} checks)")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _select_bin_dir(
    raw: str | None,
    skip_build: bool,
    parser: argparse.ArgumentParser,
) -> Path | None:
    """Resolve an explicit binary directory without silently rebuilding it."""

    if raw is None:
        return None
    bin_dir = Path(raw).expanduser().resolve()
    if not skip_build:
        return bin_dir
    missing = [
        name
        for name, _ in _go_build_targets(REPO_ROOT)
        if not (bin_dir / name).is_file() or not os.access(bin_dir / name, os.X_OK)
    ]
    if missing:
        parser.error(
            "--skip-build requires every product executable in --bin-dir; "
            "missing: " + ", ".join(sorted(missing))
        )
    return bin_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="e2e_runner.py",
        description=(
            "Run the Locklark M5 opaque-box E2E suite. Tests are registered "
            "in tests/e2e/tier*.py and executed against real product binaries."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--tier",
        choices=["1", "2", "3", "4", "all"],
        default="all",
        help="only run tests in this tier",
    )
    parser.add_argument(
        "--feature",
        action="append",
        default=[],
        metavar="F1[,F2,...]|all",
        help="only run tests touching these features (repeatable)",
    )
    parser.add_argument(
        "--id",
        default=None,
        metavar="SUBSTRING",
        help="only run tests whose test_id contains this substring",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list matching tests and registration counts, then exit",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        metavar="PATH",
        help="write the structured JSON report to PATH",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 when any test fails or is PENDING_FEATURE",
    )
    parser.add_argument(
        "--bin-dir",
        default=None,
        metavar="DIR",
        help=(
            "explicit directory containing or receiving the product binaries; "
            "with --skip-build, fail instead of rebuilding when any are missing"
        ),
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help=(
            "reuse prebuilt binaries instead of invoking go build; "
            "with --bin-dir, every required executable must already exist"
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help="accepted for CLI compatibility (execution remains isolated)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="verify the harness itself against real compiled binaries",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be a positive integer")
    all_features, feature_filter = _parse_feature_filter(parser, args.feature)
    bin_dir = _select_bin_dir(args.bin_dir, args.skip_build, parser)

    if args.self_test:
        try:
            bin_dir = ensure_binaries_built(
                REPO_ROOT, bin_dir=bin_dir, skip_build=args.skip_build
            )
        except Exception as exc:  # noqa: BLE001 - actionable build failure
            print(f"e2e_runner: cannot build binaries: {exc}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return 1
        try:
            return _run_self_test(bin_dir)
        except Exception:  # traceback already printed by the check
            return 1

    try:
        discover_test_modules()
    except RuntimeError as exc:
        print(f"e2e_runner: {exc}", file=sys.stderr)
        return 1

    specs = select_tests(
        args.tier, all_features, feature_filter, args.id
    )
    if args.list:
        _print_list(specs)
        return 0

    start_all = time.monotonic()
    if specs:
        bin_dir = ensure_binaries_built(
            REPO_ROOT, bin_dir=bin_dir, skip_build=args.skip_build
        )
    else:
        # No selected test can use a binary; keep the progressive smoke run
        # quick and avoid requiring a Go toolchain when no suite modules exist.
        print("No E2E tests matched the selected filters.", file=sys.stderr)
        if bin_dir is None:
            bin_dir = ensure_vm_temp_root() / "e2e-bin"

    report = run_tests(specs, bin_dir, start_all)
    report["summary"]["strict"] = bool(args.strict)
    _print_summary(report, bool(args.strict))

    if args.json_out:
        _write_json_report(args.json_out, report)
        print(f"JSON report written to {args.json_out}")

    if report["summary"]["fail"] > 0:
        return 1
    if args.strict and report["summary"]["pending_feature"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
