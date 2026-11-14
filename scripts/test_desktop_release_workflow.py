#!/usr/bin/env python3
"""Focused source contracts for the desktop repository_dispatch release DAG.

These tests parse the checked-in workflow and assert trigger, authorization,
checkout trust, dependency, permission, provisioning, and verifier-location
contracts. They do not dispatch a release, call GitHub, read secrets, build an
artifact, or prove external policy acceptance.

Future CI hook (not added to check.yml in this checkpoint):
    python3 -m unittest scripts/test_desktop_release_workflow.py

Requires the test-only PyYAML==6.0.3 pin in scripts/requirements-test.txt.
"""

from __future__ import annotations

import copy
import re
import unittest
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "desktop-release.yml"
OLD_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
MACOS_SCRIPT = ROOT / "scripts" / "macos_release.sh"
CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SETUP_GO = "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff"
SETUP_BUN = "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6"


def needs(job: dict[str, Any]) -> set[str]:
    value = job.get("needs", [])
    if isinstance(value, str):
        return {value}
    return set(value)


def steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    value = job.get("steps", [])
    return [step for step in value if isinstance(step, dict)]


def run_text(job: dict[str, Any]) -> str:
    return "\n".join(str(step.get("run", "")) for step in steps(job))


MYGO_BUILD_RE = re.compile(
    r'go\s+run\s+"?github\.com/egoist/mygo/cmd/mygo@[^\s"]+"?\s+build\b'
)
WINDOWS_PLATFORM_RE = re.compile(r'-platform\s+"?windows/amd64"?')
MACOS_RELEASE_RE = re.compile(r'(?<![\w./-])\./scripts/macos_release\.sh\b')


def primary_build_errors(
    workflow: dict[str, Any], macos_script: str
) -> list[str]:
    """Return violations of the single-primary-builder contract."""

    jobs = workflow.get("jobs", {})
    errors: list[str] = []

    platform_jobs = {
        name
        for name in jobs
        if any(token in name.lower() for token in ("windows", "macos", "darwin"))
    }
    if platform_jobs != {"windows", "macos"}:
        errors.append(f"platform job names are {sorted(platform_jobs)}")
    if any("matrix" in job for job in jobs.values()):
        errors.append("platform jobs must not use a build matrix")

    windows_run = run_text(jobs.get("windows", {}))
    if len(MYGO_BUILD_RE.findall(windows_run)) != 1:
        errors.append("windows job must contain exactly one MyGo build")
    if len(WINDOWS_PLATFORM_RE.findall(windows_run)) != 1:
        errors.append("windows job must contain exactly one windows/amd64 build")
    if MACOS_RELEASE_RE.search(windows_run):
        errors.append("windows job must not invoke the macOS release script")

    macos_run = run_text(jobs.get("macos", {}))
    if len(MACOS_RELEASE_RE.findall(macos_run)) != 1:
        errors.append("macos job must invoke macos_release.sh exactly once")
    if MYGO_BUILD_RE.search(macos_run):
        errors.append("macos job must delegate its MyGo build to macos_release.sh")
    if WINDOWS_PLATFORM_RE.search(macos_run):
        errors.append("macos job must not build a Windows platform")

    if len(MYGO_BUILD_RE.findall(macos_script)) != 1:
        errors.append("macos_release.sh must contain exactly one MyGo build")
    if macos_script.count("darwin/universal") != 1:
        errors.append("macos_release.sh must build darwin/universal exactly once")

    for forbidden in ("authorize", "draft-release", "verify-release"):
        forbidden_run = run_text(jobs.get(forbidden, {}))
        if (
            MYGO_BUILD_RE.search(forbidden_run)
            or WINDOWS_PLATFORM_RE.search(forbidden_run)
            or MACOS_RELEASE_RE.search(forbidden_run)
        ):
            errors.append(f"{forbidden} must not invoke a primary builder")
    return errors


def checkouts(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        step
        for step in steps(job)
        if isinstance(step.get("uses"), str)
        and step["uses"].startswith("actions/checkout@")
    ]


class DesktopReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.text)
        cls.jobs = cls.workflow["jobs"]
        cls.macos_script = MACOS_SCRIPT.read_text(encoding="utf-8")

    def test_only_repository_dispatch_trigger_and_no_legacy_workflow(self) -> None:
        self.assertFalse(OLD_WORKFLOW.exists())
        self.assertEqual(set(self.workflow["on"]), {"repository_dispatch"})
        trigger = self.workflow["on"]["repository_dispatch"]
        self.assertEqual(trigger["types"], ["desktop-release"])
        self.assertNotIn("workflow_run", self.text)
        self.assertNotIn("github.event.client_payload", self.text)
        self.assertNotIn("push:", self.text)

    def test_authorize_runs_first_with_read_only_permissions(self) -> None:
        self.assertEqual(list(self.jobs)[0], "authorize")
        authorize = self.jobs["authorize"]
        self.assertNotIn("environment", authorize)
        self.assertEqual(
            authorize["permissions"],
            {"contents": "read", "actions": "read"},
        )
        self.assertEqual(
            set(authorize["outputs"]),
            {"tag", "commit", "version", "prerelease"},
        )
        self.assertNotIn("secrets.", yaml.safe_dump(authorize))

        authorize_checkouts = checkouts(authorize)
        self.assertEqual(len(authorize_checkouts), 1)
        checkout = authorize_checkouts[0]
        self.assertEqual(checkout["uses"], CHECKOUT)
        with_args = checkout["with"]
        self.assertEqual(with_args["ref"], "${{ github.workflow_sha }}")
        self.assertEqual(with_args["fetch-depth"], 0)
        self.assertIs(with_args["fetch-tags"], True)
        self.assertIs(with_args["persist-credentials"], False)

        run = run_text(authorize)
        for required in (
            '--event "$GITHUB_EVENT_PATH"',
            '--repository "$GITHUB_REPOSITORY"',
            '--git-repo .',
            '--run-id "$GITHUB_RUN_ID"',
            '--run-attempt "$GITHUB_RUN_ATTEMPT"',
            '--sha "$GITHUB_SHA"',
            '--workflow-sha "$GITHUB_WORKFLOW_SHA"',
            '--github-output "$GITHUB_OUTPUT"',
        ):
            self.assertIn(required, run)
        self.assertIn(
            "python3 scripts/desktop_release_routing.py", run
        )
        self.assertEqual(
            authorize["steps"][-1]["env"], {"GH_TOKEN": "${{ github.token }}"}
        )

    def test_all_downstream_jobs_depend_on_authorize(self) -> None:
        self.assertEqual(
            set(self.jobs),
            {
                "authorize",
                "draft-release",
                "windows",
                "macos",
                "verify-release",
            },
        )
        for name in ("draft-release", "windows", "macos", "verify-release"):
            self.assertIn("authorize", needs(self.jobs[name]))
        self.assertEqual(needs(self.jobs["windows"]), {"authorize", "draft-release"})
        self.assertEqual(needs(self.jobs["macos"]), {"authorize", "draft-release"})
        self.assertEqual(
            needs(self.jobs["verify-release"]),
            {"authorize", "draft-release", "windows", "macos"},
        )

    def test_draft_and_build_jobs_use_validated_outputs_only(self) -> None:
        draft = self.jobs["draft-release"]
        self.assertEqual(draft["environment"], "production")
        self.assertEqual(draft["permissions"], {"contents": "write"})
        self.assertEqual(
            draft["env"]["RELEASE_TAG"], "${{ needs.authorize.outputs.tag }}"
        )
        self.assertEqual(
            draft["env"]["LOCKLARK_VERSION"],
            "${{ needs.authorize.outputs.version }}",
        )
        self.assertEqual(
            draft["env"]["PRERELEASE"],
            "${{ needs.authorize.outputs.prerelease }}",
        )
        self.assertEqual(
            checkouts(draft)[0]["with"]["ref"],
            "${{ needs.authorize.outputs.commit }}",
        )

        for name in ("windows", "macos"):
            job = self.jobs[name]
            self.assertEqual(job["environment"], "production")
            self.assertEqual(job["permissions"], {"contents": "write"})
            with_args = checkouts(job)[0]["with"]
            self.assertEqual(
                with_args["ref"], "${{ needs.authorize.outputs.commit }}"
            )
            self.assertIs(with_args["persist-credentials"], False)
            uses = [step.get("uses") for step in steps(job)]
            self.assertIn(SETUP_GO, uses)
            self.assertIn(SETUP_BUN, uses)

        self.assertEqual(self.workflow["env"]["MYGO_VERSION"], "v0.7.4")
        self.assertIn("mygo@$env:MYGO_VERSION", run_text(self.jobs["windows"]))
        mac_run = run_text(self.jobs["macos"])
        self.assertIn("./scripts/macos_release.sh --upload", mac_run)
        self.assertIn("notarytool store-credentials", mac_run)
        self.assertIn("codesign --verify --deep --strict", mac_run)
        self.assertIn("xcrun stapler validate", mac_run)

    def test_verifier_checks_out_trusted_workflow_sha(self) -> None:
        verifier = self.jobs["verify-release"]
        self.assertEqual(verifier["permissions"], {"contents": "write"})
        self.assertNotIn("environment", verifier)
        self.assertEqual(
            needs(verifier),
            {"authorize", "draft-release", "windows", "macos"},
        )

        verifier_checkouts = checkouts(verifier)
        self.assertEqual(len(verifier_checkouts), 1)
        with_args = verifier_checkouts[0]["with"]
        self.assertEqual(with_args["ref"], "${{ github.workflow_sha }}")
        self.assertIs(with_args["persist-credentials"], False)
        self.assertNotIn(
            "${{ needs.authorize.outputs.commit }}", str(with_args)
        )
        uses = [step.get("uses") for step in steps(verifier)]
        self.assertIn(SETUP_GO, uses)
        self.assertIn(SETUP_BUN, uses)

        run = run_text(verifier)
        self.assertIn("python3 scripts/verify_desktop_release.py", run)
        self.assertIn('--version "$LOCKLARK_VERSION"', run)
        self.assertIn('--public-key "$public_key"', run)
        self.assertIn(
            'gh release download "$RELEASE_TAG"', run
        )
        self.assertIn(
            'gh release upload "$RELEASE_TAG"', run
        )

    def test_no_payload_expressions_in_run_scripts_and_no_weakening(self) -> None:
        for name, job in self.jobs.items():
            run = run_text(job)
            self.assertNotIn("${{", run, name)
            self.assertNotIn("github.event.client_payload", run, name)
            self.assertNotIn("continue-on-error", yaml.safe_dump(job), name)
            self.assertNotIn("if: always()", yaml.safe_dump(job), name)

    def test_all_checkouts_disable_persisted_credentials(self) -> None:
        for name, job in self.jobs.items():
            for checkout in checkouts(job):
                self.assertEqual(checkout["uses"], CHECKOUT, name)
                self.assertIs(
                    checkout["with"]["persist-credentials"], False, name
                )

    def test_action_pins_and_permission_boundaries(self) -> None:
        pinned = re.compile(r"^[^@]+@[0-9a-f]{40}$")
        for name, job in self.jobs.items():
            for step in steps(job):
                uses = step.get("uses")
                if isinstance(uses, str):
                    self.assertRegex(uses, pinned, name)
            permissions = job.get("permissions", {})
            if name != "authorize":
                self.assertNotIn("actions", permissions, name)
                self.assertEqual(permissions, {"contents": "write"}, name)
            else:
                self.assertEqual(permissions["contents"], "read")
                self.assertEqual(permissions["actions"], "read")

    def test_primary_build_guard_accepts_current_single_builders(self) -> None:
        self.assertEqual(
            primary_build_errors(self.workflow, self.macos_script),
            [],
        )

    def test_primary_build_guard_rejects_duplicate_build_fixtures(self) -> None:
        duplicate_draft = copy.deepcopy(self.workflow)
        duplicate_draft["jobs"]["draft-release"]["steps"].append(
            {
                "name": "Duplicate primary build",
                "run": (
                    'go run "github.com/egoist/mygo/cmd/mygo@'
                    '$env:MYGO_VERSION" build -platform "windows/amd64"'
                ),
            }
        )
        errors = primary_build_errors(duplicate_draft, self.macos_script)
        self.assertTrue(errors)
        self.assertTrue(
            any("draft-release" in error for error in errors), errors
        )

        duplicate_platform = copy.deepcopy(self.workflow)
        duplicate_platform["jobs"]["windows-secondary"] = copy.deepcopy(
            duplicate_platform["jobs"]["windows"]
        )
        errors = primary_build_errors(duplicate_platform, self.macos_script)
        self.assertTrue(errors)
        self.assertTrue(
            any("platform job names" in error for error in errors), errors
        )


if __name__ == "__main__":
    unittest.main()
