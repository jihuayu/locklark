#!/usr/bin/env python3
"""Dependency and aggregate contract for the extension-producer workflow."""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "check.yml"
JOBS = (
    "linux-build",
    "contracts",
    "extension-producer",
    "go",
    "desktop-macos",
    "web-core",
    "web-browsers",
    "web",
    "android",
    "ios",
)


def text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def block(name: str) -> str:
    source = text()
    start = source.index(f"  {name}:\n")
    end = len(source)
    for line in source[start + 1 :].splitlines(keepends=True):
        if line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
            end = start + source[start + 1 :].index(line)
            break
    return source[start:end]


def stage_shell(name: str) -> str:
    source = block(name)
    marker = "      - name: Verify and stage extension producer\n        run: |\n"
    start = source.index(marker) + len(marker)
    shell = []
    for line in source[start:].splitlines():
        if line.startswith("          "):
            shell.append(line[10:])
        elif not line.strip() and shell:
            shell.append("")
        elif shell:
            break
    return "\n".join(shell)


def step_text(job_name: str, step_name: str) -> str:
    source = block(job_name)
    marker = f"      - name: {step_name}\n"
    if source.count(marker) != 1:
        raise AssertionError("workflow step is not unique")
    lines = source.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line == marker)
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.match(r"^ {6}- ", lines[index]):
            end = index
            break
    return "".join(lines[start:end])


def step_commands(job_name: str, step_name: str) -> list[str]:
    step = step_text(job_name, step_name)
    run_marker = "        run: |\n"
    if step.count(run_marker) != 1:
        raise AssertionError("workflow step must declare exactly one run: |")
    run_at = step.index(run_marker) + len(run_marker)
    commands = []
    for line in step[run_at:].splitlines():
        if line.startswith("          "):
            commands.append(line[10:])
        elif line.strip():
            break
    return commands


def step_fields(job_name: str, step_name: str) -> dict[str, str]:
    fields = {}
    for line in step_text(job_name, step_name).splitlines():
        match = re.fullmatch(r" {8}([a-z][a-z0-9-]*):(?: (.*))?", line)
        if match:
            key, value = match.groups()
            if key in fields:
                raise AssertionError("step field is not unique")
            fields[key] = value or ""
    return fields


def web_core_step_enabled(
    name: str, *, previous_failure: bool = False, cancelled: bool = False,
    outcomes: dict[str, str] | None = None,
) -> bool:
    """Project the actual step's restricted if grammar, including implicit success()."""
    expression = step_fields("web-core", name).get("if")
    if expression is None:
        return not previous_failure and not cancelled
    wrapped = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", expression)
    if not wrapped:
        raise AssertionError("independent condition must be an expression")
    status_function = False
    values = []
    for clause in wrapped[1].split("&&"):
        clause = clause.strip()
        if clause == "!cancelled()":
            status_function = True
            values.append(not cancelled)
            continue
        comparison = re.fullmatch(r"steps\.([a-z][a-z0-9_]*)\.outcome == 'success'", clause)
        if not comparison:
            raise AssertionError("unsupported independent condition")
        values.append((outcomes or {}).get(comparison[1], "") == "success")
    # GitHub adds success() unless the expression contains a status function.
    # Reading only ready.outcome would still suppress steps after a failure.
    return all(values) and (status_function or (not previous_failure and not cancelled))


def ci_required_shell() -> str:
    source = block("ci-required")
    marker = "        run: |\n"
    start = source.index(marker) + len(marker)
    lines = source[start:].splitlines()
    shell = []
    for line in lines:
        if line.startswith("          "):
            shell.append(line[10:])
        elif not line.strip() and shell:
            shell.append("")
    return "\n".join(shell)


class VaultFileProductCIContract(unittest.TestCase):
    STEP = "Test Go packages and native OpenSSH transport"
    MINIMUM = "go test -count=1 -run '^TestVaultFileResumeProductMinimum$' ./cmd/locklark"
    REMAINING = "go test -count=1 -skip '^TestVaultFileResumeProductMinimum$' ./..."
    EXIT_CHECK = "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"

    @classmethod
    def linux_commands(cls) -> list[str]:
        commands = step_commands("go", cls.STEP)
        split = commands.index("} else {")
        if commands[-1] != "}" or commands[split - 3:split] != [
            "if ($IsWindows) {",
            "  python scripts/personal_test_partition.py",
            "  " + cls.EXIT_CHECK,
        ]:
            raise AssertionError("Windows partition or Linux branch changed")
        return [line[2:] for line in commands[split + 1:-1]]

    def test_linux_reuses_one_product_and_partitions_minimum_before_remaining(self):
        commands = self.linux_commands()
        self.assertEqual(commands, [
            "$vaultFileProduct = Join-Path $env:RUNNER_TEMP 'locklark-bin/locklark'",
            "if (-not [System.IO.Path]::IsPathFullyQualified($vaultFileProduct) -or -not "
            "(Test-Path -LiteralPath $vaultFileProduct -PathType Leaf)) "
            "{ throw 'VAULTFILE_PRODUCT_UNAVAILABLE' }",
            "$env:LOCKLARK_TEST_VAULTFILE_PRODUCT = $vaultFileProduct",
            self.MINIMUM, self.EXIT_CHECK, self.REMAINING, self.EXIT_CHECK,
        ])
        self.assertEqual(text().count("LOCKLARK_TEST_VAULTFILE_PRODUCT"), 1)
        self.assertNotIn("go build", "\n".join(commands))
        self.assertEqual(block("linux-build").count(
            'go build -trimpath -o "$bin/locklark" ./cmd/locklark'
        ), 1)
        self.assertIn("if-no-files-found: error", block("linux-build"))
        download = step_text("go", "Download Linux primary binaries")
        self.assertIn("if: runner.os == 'Linux'", download)
        self.assertIn("name: locklark-linux-bin", download)
        self.assertIn("path: ${{ runner.temp }}/locklark-bin", download)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh dispatch mock is unavailable")
    def test_actual_linux_commands_with_strict_mock_only_dispatch_and_propagate_exit(self):
        # This fixture cannot execute a product or build anything. It checks
        # only the extracted PowerShell's scheduling, argv, env and exit codes.
        expected = [
            ["test", "-count=1", "-run", "^TestVaultFileResumeProductMinimum$", "./cmd/locklark"],
            ["test", "-count=1", "-skip", "^TestVaultFileResumeProductMinimum$", "./..."],
        ]
        for kind, fail_at, code, calls in (
            ("file", -1, 0, 2), ("file", 0, 7, 1), ("file", 1, 11, 2),
            ("missing", -1, None, 0), ("directory", -1, None, 0),
            ("relative", -1, None, 0),
        ):
            with self.subTest(kind=kind, fail_at=fail_at), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                runner = root / "runner"
                product = runner / "locklark-bin" / "locklark"
                product.parent.mkdir(parents=True)
                if kind == "directory":
                    product.mkdir()
                elif kind != "missing":
                    product.write_text("not an executable product", encoding="utf-8")
                    product.chmod(0o600)
                fake_bin = root / "bin"
                fake_bin.mkdir()
                log = root / "go-argv.jsonl"
                fake_go = fake_bin / "go"
                fake_go.write_text("#!" + sys.executable + "\n" + (
                    "import json, os, pathlib, sys\n"
                    "log = pathlib.Path(os.environ['VAULTFILE_DISPATCH_LOG'])\n"
                    "seen = log.read_text().splitlines() if log.exists() else []\n"
                    "expected = json.loads(os.environ['VAULTFILE_DISPATCH_EXPECTED'])\n"
                    "index = len(seen)\n"
                    "if index >= len(expected) or sys.argv[1:] != expected[index]: sys.exit(85)\n"
                    "if os.environ.get('LOCKLARK_TEST_VAULTFILE_PRODUCT') != os.environ['VAULTFILE_DISPATCH_PRODUCT']: sys.exit(86)\n"
                    "with log.open('a') as output: output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                    "sys.exit(int(os.environ['VAULTFILE_DISPATCH_EXIT']) if index == int(os.environ['VAULTFILE_DISPATCH_FAIL_AT']) else 0)\n"
                ), encoding="utf-8")
                fake_go.chmod(0o755)
                script = root / "dispatch.ps1"
                script.write_text(
                    "$ErrorActionPreference = 'Stop'\n" + "\n".join(self.linux_commands()) + "\n",
                    encoding="utf-8",
                )
                env = {**os.environ, "RUNNER_TEMP": "runner" if kind == "relative" else str(runner),
                       "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
                       "VAULTFILE_DISPATCH_LOG": str(log),
                       "VAULTFILE_DISPATCH_EXPECTED": json.dumps(expected),
                       "VAULTFILE_DISPATCH_PRODUCT": str(product),
                       "VAULTFILE_DISPATCH_FAIL_AT": str(fail_at),
                       "VAULTFILE_DISPATCH_EXIT": str(code or 0)}
                env.pop("LOCKLARK_TEST_VAULTFILE_PRODUCT", None)
                result = subprocess.run(
                    [shutil.which("pwsh"), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
                    env=env, cwd=root, text=True, capture_output=True, check=False,
                )
                if code is None:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("VAULTFILE_PRODUCT_UNAVAILABLE", result.stderr)
                else:
                    self.assertEqual(result.returncode, code, result.stderr)
                actual = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
                self.assertEqual(actual, expected[:calls])


class ExtensionProducerWorkflowContract(unittest.TestCase):
    def test_job_dependencies_and_single_artifact(self):
        source = text()
        producer = block("extension-producer")
        self.assertIn("    needs: [contracts]\n", producer)
        self.assertIn("python3 -m browserrelease --product chromium", producer)
        self.assertIn("python3 -m browserrelease --product \"$product\"", producer)
        self.assertIn("--prepared-dir", producer)
        self.assertIn("--dist", producer)
        self.assertNotIn("browser-extension/build.js", producer)
        self.assertIn("name: locklark-extension-producer", producer)
        self.assertIn("unpacked", producer)
        self.assertIn("prepared/v2pairs", producer)
        self.assertIn("legacy/v1pairs", producer)
        self.assertIn("retention-days: 14", producer)
        self.assertEqual(producer.count("name: locklark-extension-producer"), 1)
        self.assertNotIn("locklark-extension-unsigned", source)
        for job in ("web-core", "web-browsers", "desktop-macos"):
            self.assertIn(
                "needs: [linux-build, contracts, extension-producer]"
                if job != "desktop-macos"
                else "needs: [contracts, extension-producer]",
                block(job),
            )
        desktop = block("desktop-macos")
        self.assertIn("LOCKLARK_BROWSER_EXTENSION_SAFARI", desktop)
        self.assertIn("safari/scripts/build_safari.sh", desktop)
        self.assertNotIn("/unpacked/chromium\n", desktop.split("Test Safari")[1])
        web = block("web")
        self.assertIn("needs: [extension-producer, web-core, web-browsers]", web)
        self.assertIn("EXTENSION_PRODUCER_RESULT", web)
        required = block("ci-required")
        self.assertIn("extension-producer", required.splitlines()[2])
        self.assertIn("EXTENSION_PRODUCER_RESULT", required)

    def test_actual_stage_shell_exports_canonical_paths_and_copies(self):
        for job in ("web-core", "web-browsers", "desktop-macos"):
            with self.subTest(job=job), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                runner = root / "runner"
                workspace = root / "workspace"
                artifact = runner / "locklark-extension-producer"
                workspace.mkdir()
                env_file = root / "github-env"
                fake_bin = root / "bin"
                fake_bin.mkdir()
                fake_python = fake_bin / "python3"
                fake_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                fake_python.chmod(0o755)
                for product in ("chromium", "firefox", "safari"):
                    (artifact / "unpacked" / product).mkdir(parents=True)
                    (artifact / "unpacked" / product / "manifest.json").write_text(
                        product, encoding="utf-8"
                    )
                (artifact / "prepared" / "v2pairs").mkdir(parents=True)
                (artifact / "prepared" / "v2pairs" / "pair").write_text(
                    "pair", encoding="utf-8"
                )
                result = subprocess.run(
                    ["bash", "-c", stage_shell(job)],
                    env={
                        **os.environ,
                        "RUNNER_TEMP": str(runner),
                        "GITHUB_WORKSPACE": str(workspace),
                        "GITHUB_ENV": str(env_file),
                        "PATH": str(fake_bin) + ":" + os.environ.get("PATH", ""),
                    },
                    text=True, capture_output=True, check=False, cwd=workspace,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                values = {}
                for line in env_file.read_text(encoding="utf-8").splitlines():
                    key, _, value = line.partition("=")
                    values[key] = value
                self.assertEqual(values["LOCKLARK_BROWSER_REQUIRE_PREBUILT"], "1")
                self.assertEqual(
                    values["LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR"],
                    str(artifact / "prepared" / "v2pairs"),
                )
                for product in ("chromium", "firefox", "safari"):
                    target = workspace / "browser-extension" / "dist" / product
                    self.assertEqual(
                        values["LOCKLARK_BROWSER_EXTENSION_" + product.upper()],
                        str(target),
                    )
                    self.assertEqual(
                        (target / "manifest.json").read_text(encoding="utf-8"),
                        product,
                    )

    def test_step_commands_does_not_read_a_later_step_run(self):
        source = """  extension-producer:
    needs: [contracts]
    steps:
      - name: Run original release and legacy unit tests
        uses: actions/checkout@v4
      - name: Later step
        run: |
          node --test scripts/test_browser_edge_install.mjs
"""
        self.assertEqual(
            source.count("node --test scripts/test_browser_edge_install.mjs"),
            1,
        )
        with mock.patch("scripts.test_ci_extension_producer.text", return_value=source):
            with self.assertRaisesRegex(AssertionError, "run: \\|"):
                step_commands("extension-producer", "Run original release and legacy unit tests")

    def test_edge_install_contract_runs_once_after_official_chromium(self):
        prepare = "Prepare Chromium once and strict smoke"
        units = "Run original release and legacy unit tests"
        edge = "node --test scripts/test_browser_edge_install.mjs"
        chromium = (
            'python3 -m browserrelease --product chromium '
            '--output "$out/prepared/v2pairs"'
        )
        strict = "python3 -m browserrelease.prebuilt --product chromium \\"
        producer = block("extension-producer")
        self.assertLess(producer.index(prepare), producer.index(units))
        commands = step_commands("extension-producer", prepare)
        prepare_at = commands.index(chromium)
        self.assertEqual(commands[prepare_at + 1], strict)
        self.assertIn(
            '--prepared-dir "$out/prepared/v2pairs" '
            "--dist browser-extension/dist/chromium",
            commands[prepare_at + 2],
        )
        unit_commands = step_commands("extension-producer", units)
        self.assertEqual(
            [line for line in unit_commands if line == edge], [edge]
        )
        early = step_text("web-core", "Test browser extension")
        self.assertIn("node --test ", early)
        self.assertNotIn(edge, early)
        self.assertEqual(text().count(edge), 1)

    def test_actual_ci_required_shell_rejects_non_success(self):
        shell = ci_required_shell()
        self.assertIn("required='linux-build contracts extension-producer", shell)
        base = {f"{job.upper().replace('-', '_')}_RESULT": "success" for job in JOBS}
        base["EXTENSION_PRODUCER_RESULT"] = "success"
        success = subprocess.run(
            ["bash", "-c", shell], env={**os.environ, **base},
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(success.returncode, 0, success.stderr)
        for value in ("failure", "skipped", "cancelled", ""):
            env = {**base, "EXTENSION_PRODUCER_RESULT": value}
            result = subprocess.run(
                ["bash", "-c", shell], env={**os.environ, **env},
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0, value)
            self.assertIn("extension-producer=", result.stderr)


class WebCoreIndependentAcceptanceContract(unittest.TestCase):
    READY = "Install native GUI acceptance tools"
    PEER = "Install independent notes KDBX reader"
    GATE = "Test reconciled E2E gates and component contracts"
    CHROMIUM = "Test browser extension DOM"
    FIREFOX = "Test Firefox browser extension DOM"
    UPLOAD = "Preserve synthetic popup UI screenshots"
    READY_STEPS = (
        "Test native desktop daily tools and clipboard ownership",
        "Test native desktop global quick search",
        PEER, CHROMIUM, FIREFOX,
    )
    PEER_STEPS = (
        "Test native imported multiline login notes and failure privacy",
        "Test native SSH approvals, real OpenSSH forwarding and encrypted export",
    )
    FOLLOWUPS = READY_STEPS + PEER_STEPS + (UPLOAD,)

    @staticmethod
    def ready_outcomes() -> dict[str, str]:
        return {name: "success" for name in (
            "native_gui_ready", "notes_peer_ready", "chromium_dom", "firefox_dom",
        )}

    def test_ready_keeps_bootstrap_failure_gate_and_prebuilt_smoke_order(self):
        source = block("web-core")
        ids = {
            self.READY: "native_gui_ready", self.PEER: "notes_peer_ready",
            self.CHROMIUM: "chromium_dom", self.FIREFOX: "firefox_dom",
        }
        for name, identifier in ids.items():
            self.assertEqual(step_fields("web-core", name).get("id"), identifier)
        self.assertNotIn("if", step_fields("web-core", self.READY))
        self.assertNotIn("if", step_fields("web-core", self.GATE))
        self.assertNotIn("continue-on-error:", source)
        self.assertNotRegex(source, r"(?m)^\s*go build\b")
        self.assertIn('--skip-build --bin-dir "$RUNNER_TEMP/locklark-bin"', step_text("web-core", self.GATE))
        order = [
            "Download Linux primary binaries", "Make Linux binaries executable",
            "Smoke test downloaded CLI before acceptance", "Test browser extension",
            self.READY, self.GATE,
        ]
        positions = [source.index(f"      - name: {name}\n") for name in order]
        self.assertEqual(positions, sorted(positions))
        self.assertFalse(web_core_step_enabled(self.READY, previous_failure=True))
        self.assertFalse(web_core_step_enabled(self.READY, cancelled=True))

    def test_failed_gate_does_not_block_independent_steps(self):
        for previous_failure in (False, True):
            for name in self.FOLLOWUPS:
                with self.subTest(step=name, previous_failure=previous_failure):
                    self.assertTrue(web_core_step_enabled(
                        name, previous_failure=previous_failure, outcomes=self.ready_outcomes(),
                    ))

    def test_unready_or_cancelled_blocks_every_independent_step(self):
        for status in ("failure", "skipped", "cancelled", ""):
            outcomes = {**self.ready_outcomes(), "native_gui_ready": status}
            for name in self.FOLLOWUPS:
                with self.subTest(step=name, ready=status):
                    self.assertFalse(web_core_step_enabled(name, previous_failure=True, outcomes=outcomes))
        for name in self.FOLLOWUPS:
            self.assertFalse(web_core_step_enabled(
                name, cancelled=True, outcomes=self.ready_outcomes(),
            ))

    def test_peer_failure_blocks_only_notes_and_ssh(self):
        for status in ("failure", "skipped", "cancelled", ""):
            outcomes = {**self.ready_outcomes(), "notes_peer_ready": status}
            for name in self.PEER_STEPS:
                self.assertFalse(web_core_step_enabled(name, previous_failure=True, outcomes=outcomes))
            for name in self.READY_STEPS + (self.UPLOAD,):
                self.assertTrue(web_core_step_enabled(name, previous_failure=True, outcomes=outcomes))
        # A notes assertion failure is not a prerequisite failure for SSH.
        self.assertTrue(web_core_step_enabled(
            self.PEER_STEPS[1], previous_failure=True, outcomes=self.ready_outcomes(),
        ))

    def test_dom_failures_do_not_block_each_other_or_upload_failed_screenshots(self):
        for identifier in ("chromium_dom", "firefox_dom"):
            for status in ("failure", "skipped", "cancelled", ""):
                outcomes = {**self.ready_outcomes(), identifier: status}
                for name in (self.CHROMIUM, self.FIREFOX):
                    self.assertTrue(web_core_step_enabled(name, previous_failure=True, outcomes=outcomes))
                self.assertFalse(web_core_step_enabled(self.UPLOAD, previous_failure=True, outcomes=outcomes))

    def test_projection_preserves_implicit_success_and_refuses_broader_grammar(self):
        name = self.READY_STEPS[0]
        source = text()
        original = step_text("web-core", name)
        condition = step_fields("web-core", name)["if"]
        without_status = condition.replace("!cancelled() && ", "")
        changed = original.replace(condition, without_status)
        with mock.patch("scripts.test_ci_extension_producer.text", return_value=source.replace(original, changed)):
            self.assertTrue(web_core_step_enabled(name, outcomes=self.ready_outcomes()))
            self.assertFalse(web_core_step_enabled(name, previous_failure=True, outcomes=self.ready_outcomes()))
        for expression in ("${{ always() }}", "${{ !cancelled() || true }}"):
            changed = original.replace(condition, expression)
            with mock.patch("scripts.test_ci_extension_producer.text", return_value=source.replace(original, changed)):
                with self.assertRaisesRegex(AssertionError, "unsupported independent condition"):
                    web_core_step_enabled(name, outcomes=self.ready_outcomes())

    def test_actual_aggregates_never_turn_a_failed_web_core_green(self):
        shells = (
            "\n".join(step_commands("web", "Require every Web check to succeed")),
            ci_required_shell(),
        )
        base = {f"{job.upper().replace('-', '_')}_RESULT": "success" for job in JOBS}
        for shell in shells:
            passed = subprocess.run(
                ["bash", "-c", shell], env={**os.environ, **base},
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(passed.returncode, 0)
            for status in ("failure", "skipped", "cancelled", ""):
                failed = subprocess.run(
                    ["bash", "-c", shell], env={**os.environ, **base, "WEB_CORE_RESULT": status},
                    text=True, capture_output=True, check=False,
                )
                self.assertNotEqual(failed.returncode, 0, status)


if __name__ == "__main__":
    unittest.main()
