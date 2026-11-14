#!/usr/bin/env python3
"""Dependency and aggregate contract for the extension-producer workflow."""
from __future__ import annotations

import os
import pathlib
import subprocess
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
        web = block("web")
        self.assertIn("needs: [extension-producer, web-core, web-browsers]", web)
        self.assertIn("EXTENSION_PRODUCER_RESULT", web)
        required = block("ci-required")
        self.assertIn("extension-producer", required.splitlines()[2])
        self.assertIn("EXTENSION_PRODUCER_RESULT", required)

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
