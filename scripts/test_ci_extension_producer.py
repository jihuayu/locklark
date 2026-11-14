#!/usr/bin/env python3
"""Dependency and aggregate contract for the extension-producer workflow."""
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

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


def step_commands(job_name: str, step_name: str) -> list[str]:
    source = block(job_name)
    marker = f"      - name: {step_name}\n"
    if source.count(marker) != 1:
        raise AssertionError("workflow step is not unique")
    start = source.index(marker)
    run_marker = "        run: |\n"
    run_at = source.index(run_marker, start)
    commands = []
    for line in source[run_at + len(run_marker):].splitlines():
        if line.startswith("          "):
            commands.append(line[10:])
        elif line.strip():
            break
    return commands


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
        early = step_commands("web-core", "Test browser extension")
        self.assertFalse(any(edge in line for line in early))
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


if __name__ == "__main__":
    unittest.main()
