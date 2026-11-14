"""Focused contracts for the read-only desktop release trust checkpoint.

The git smoke tests build a real, temporary, test-owned repository and pin
real commits/tag objects. The API metadata contracts use an injected fake
transport. Fake GitHub metadata is not evidence that any external GitHub
policy has been configured or accepted.
"""

from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import authorize_desktop_release as trust  # noqa: E402


REPOSITORY = "acme/widget"
TAG = "v1.2.3"
RUN_ID = 123
WORKFLOW_ID = 456
REPOSITORY_ID = 100
OWNER = "acme"


def run_command(
    *args: str,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        list(args),
        cwd=cwd,
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"command failed: {' '.join(args)}\n{result.stderr.decode(errors='replace')}"
        )
    return result


class GitFixture:
    """A real, test-owned repository with graph branches but no checkout."""

    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="locklark-trust-git-")
        self.root = Path(self.temporary.name)
        run_command("git", "init", "-q", "--initial-branch=main", str(self.root))
        run_command(
            "git", "-C", str(self.root), "config", "user.name", "Release Trust Tests"
        )
        run_command(
            "git",
            "-C",
            str(self.root),
            "config",
            "user.email",
            "release-trust@example.invalid",
        )
        run_command(
            "git", "-C", str(self.root), "config", "commit.gpgSign", "false"
        )
        run_command("git", "-C", str(self.root), "config", "tag.gpgSign", "false")
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "GIT_AUTHOR_NAME": "Release Trust Tests",
                "GIT_AUTHOR_EMAIL": "release-trust@example.invalid",
                "GIT_COMMITTER_NAME": "Release Trust Tests",
                "GIT_COMMITTER_EMAIL": "release-trust@example.invalid",
                "GIT_AUTHOR_DATE": "2026-11-15T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-11-15T00:00:00Z",
            }
        )
        self.empty_tree = run_command(
            "git", "-C", str(self.root), "mktree", input_bytes=b""
        ).stdout.decode("ascii").strip()
        payload_blob = self._git(
            "hash-object",
            "-w",
            "--stdin",
            input_bytes=b"#!/bin/sh\ntouch release-tag-executed\n",
        )
        self.payload_tree = self._git(
            "mktree",
            input_bytes=(
                f"100755 blob {payload_blob}\trelease-payload.sh\n"
            ).encode("ascii"),
        )
        self.reviewed = self.commit("reviewed", tree=self.payload_tree)
        self.tip = self.commit("default branch tip", parent=self.reviewed)
        self.unreviewed = self.commit("unreviewed side commit", parent=self.tip)
        self._git("update-ref", "refs/heads/main", self.tip)

    def _git(self, *args: str, input_bytes: bytes | None = None) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.root), *args],
            input=input_bytes,
            capture_output=True,
            env=self.environment,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"git {' '.join(args)} failed: "
                f"{result.stderr.decode(errors='replace')}"
            )
        return result.stdout.decode("utf-8", errors="replace").strip()

    def commit(
        self, message: str, parent: str | None = None, tree: str | None = None
    ) -> str:
        args = ["commit-tree", tree or self.empty_tree]
        if parent is not None:
            args.extend(["-p", parent])
        args.extend(["-m", message])
        return self._git(*args)

    def lightweight_tag(self, name: str, commit: str) -> None:
        self._git("update-ref", f"refs/tags/{name}", commit)

    def annotated_tag(self, name: str, commit: str) -> None:
        self._git("tag", "-a", name, commit, "-m", f"release {name}")

    def retarget(self, name: str, commit: str) -> None:
        self._git("update-ref", f"refs/tags/{name}", commit)

    def delete_tag(self, name: str) -> None:
        self._git("update-ref", "-d", f"refs/tags/{name}")

    def ambiguous_tag(self, name: str, first: str, second: str) -> None:
        payload = (
            f"object {first}\n"
            f"object {second}\n"
            "type commit\n"
            f"tag {name}\n"
            "\n"
            "two objects in one annotated tag\n"
        ).encode("utf-8")
        oid = self._git(
            "hash-object",
            "--literally",
            "-w",
            "-t",
            "tag",
            "--stdin",
            input_bytes=payload,
        )
        # update-ref intentionally refuses malformed tag objects, so install
        # the loose ref directly. The validator must still detect the
        # ambiguous binding fields in the real tag object.
        ref_path = self.root / ".git" / "refs" / "tags" / name
        ref_path.parent.mkdir(parents=True, exist_ok=True)
        ref_path.write_text(oid + "\n", encoding="ascii")

    def close(self) -> None:
        self.temporary.cleanup()


class FakeTransport:
    """Injectable metadata transport; it has no write operation at all."""

    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = dict(responses)
        self.calls: list[tuple[str, str]] = []

    def get(self, path: str) -> trust.ApiResponse:
        self.calls.append(("get", path))
        return self._response(path)

    def get_list(self, path: str) -> trust.ApiResponse:
        self.calls.append(("get_list", path))
        return self._response(path)

    def _response(self, path: str) -> trust.ApiResponse:
        value = self.responses.get(path, trust.ApiResponse(404, None))
        if isinstance(value, trust.ApiResponse):
            return value
        return trust.ApiResponse(200, copy.deepcopy(value))


class AuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.git = GitFixture()
        self.transport = self.valid_transport()

    def tearDown(self) -> None:
        self.git.close()

    def event(
        self,
        head: str,
        *,
        head_branch: str | None = TAG,
        run_id: int = RUN_ID,
        workflow_id: int = WORKFLOW_ID,
        repository_id: int = REPOSITORY_ID,
        full_name: str = REPOSITORY,
        path: str = trust.RELEASE_WORKFLOW_PATH,
        trigger: str = "push",
        status: str = "completed",
        conclusion: str = "success",
        run_attempt: int = 1,
    ) -> dict[str, object]:
        return {
            "action": "completed",
            "repository": {
                "id": repository_id,
                "full_name": full_name,
                "default_branch": "main",
            },
            "workflow_run": {
                "id": run_id,
                "workflow_id": workflow_id,
                "path": path,
                "event": trigger,
                "status": status,
                "conclusion": conclusion,
                "head_sha": head,
                "head_branch": head_branch,
                "run_attempt": run_attempt,
                "repository": {"id": repository_id, "full_name": full_name},
                "head_repository": {"id": repository_id, "full_name": full_name},
            },
        }

    def run_payload(
        self,
        head: str,
        *,
        head_branch: str | None = TAG,
        run_id: int = RUN_ID,
        workflow_id: int = WORKFLOW_ID,
        repository_id: int = REPOSITORY_ID,
        full_name: str = REPOSITORY,
        path: str = trust.RELEASE_WORKFLOW_PATH,
        trigger: str = "push",
        status: str = "completed",
        conclusion: str = "success",
        run_attempt: int = 1,
    ) -> dict[str, object]:
        return {
            "id": run_id,
            "workflow_id": workflow_id,
            "path": path,
            "event": trigger,
            "status": status,
            "conclusion": conclusion,
            "head_sha": head,
            "head_branch": head_branch,
            "run_attempt": run_attempt,
            "repository": {"id": repository_id, "full_name": full_name},
            "head_repository": {"id": repository_id, "full_name": full_name},
        }

    def repository_payload(
        self, *, owner_type: str = "User", default_branch: str = "main"
    ) -> dict[str, object]:
        return {
            "id": REPOSITORY_ID,
            "full_name": REPOSITORY,
            "default_branch": default_branch,
            "owner": {"login": OWNER, "type": owner_type},
        }

    def valid_status_checks(self) -> dict[str, object]:
        return {
            "strict": True,
            "contexts": [trust.REQUIRED_STATUS_CHECK_CONTEXT],
            "checks": [
                {
                    "context": trust.REQUIRED_STATUS_CHECK_CONTEXT,
                    "app_id": trust.GITHUB_ACTIONS_APP_ID,
                }
            ],
        }

    def valid_reviews(self) -> dict[str, object]:
        return {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews": True,
            "require_last_push_approval": True,
            "bypass_pull_request_allowances": {
                "users": [],
                "teams": [],
                "apps": [],
            },
        }

    def valid_protection(self) -> dict[str, object]:
        return {
            "required_status_checks": self.valid_status_checks(),
            "required_pull_request_reviews": self.valid_reviews(),
            "enforce_admins": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
        }

    def valid_transport(
        self,
        *,
        owner_type: str = "User",
        head_commit: str | None = None,
        default_commit: str | None = None,
    ) -> FakeTransport:
        if head_commit is None:
            head_commit = self.git.reviewed
        if default_commit is None:
            default_commit = self.git.tip
        responses: dict[str, object] = {
            trust.repository_api(REPOSITORY): self.repository_payload(
                owner_type=owner_type
            ),
            trust.workflow_run_api(REPOSITORY, RUN_ID): self.run_payload(
                head_commit
            ),
            trust.branch_api(REPOSITORY): {
                "name": "main",
                "protected": True,
                "commit": {"sha": default_commit},
            },
            trust.branch_protection_api(REPOSITORY): self.valid_protection(),
            trust.rulesets_api(REPOSITORY): [
                {"id": 7, "target": "tag", "enforcement": "active"}
            ],
            trust.ruleset_api(REPOSITORY, 7): {
                "id": 7,
                "target": "tag",
                "enforcement": "active",
                "conditions": {
                    "ref_name": {
                        "include": [trust.TAG_REF_PATTERN],
                        "exclude": [],
                    }
                },
                "rules": [
                    {"type": "deletion"},
                    {"type": "update"},
                    {"type": "non_fast_forward"},
                ],
                "bypass_actors": [],
            },
            trust.environment_api(REPOSITORY): {
                "name": trust.PRODUCTION_ENVIRONMENT,
                "deployment_branch_policy": {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                },
            },
            trust.environment_branch_policies_api(REPOSITORY): {
                "total_count": 1,
                "branch_policies": [{"id": 1, "name": "main", "type": "branch"}],
            },
            trust.environment_secrets_api(REPOSITORY): {
                "total_count": len(trust.REQUIRED_ENVIRONMENT_SECRETS),
                "secrets": [
                    {"name": name}
                    for name in sorted(trust.REQUIRED_ENVIRONMENT_SECRETS)
                ],
            },
            trust.repository_secrets_api(REPOSITORY): {
                "total_count": 0,
                "secrets": [],
            },
        }
        if owner_type == "Organization":
            responses[trust.organization_secrets_api(OWNER)] = {
                "total_count": 0,
                "secrets": [],
            }
        return FakeTransport(responses)

    def authorize(
        self,
        transport: trust.ReadOnlyTransport | None = None,
        *,
        event: dict[str, object] | None = None,
        tag: str = TAG,
    ) -> trust.Decision:
        if event is None:
            event = self.event(self.git.reviewed)
        if transport is None:
            transport = self.transport
        return trust.authorize_desktop_release(
            event=event,
            repository=REPOSITORY,
            tag=tag,
            git_repo=self.git.root,
            transport=transport,
        )

    def assert_refused(self, decision: trust.Decision, reason: trust.Refusal) -> None:
        self.assertEqual(decision.decision, "REFUSE", decision.as_json())
        self.assertEqual(decision.reason, reason, decision.detail)
        self.assertFalse(decision.authorized)

    def gh_fixture_stdout(self, *, owner_type: str = "User") -> dict[str, str]:
        """Render the fake metadata as real ``gh --paginate --slurp`` JSON."""

        responses = self.valid_transport(owner_type=owner_type).responses
        paginated = {
            trust.rulesets_api(REPOSITORY),
            trust.environment_branch_policies_api(REPOSITORY),
            trust.environment_secrets_api(REPOSITORY),
            trust.repository_secrets_api(REPOSITORY),
            trust.organization_secrets_api(OWNER),
        }
        stdout: dict[str, str] = {}
        for path, value in responses.items():
            if isinstance(value, trust.ApiResponse):
                if value.status != 200:
                    raise AssertionError("fixture uses a non-200 API response")
                payload = value.payload
            else:
                payload = value
            if path in paginated:
                payload = [payload]
            stdout[path] = json.dumps(payload)
        return stdout

    def authorize_via_gh(
        self, stdout: dict[str, str]
    ) -> tuple[trust.Decision, list[list[str]]]:
        """Run the full validator with the real transport and fake subprocess."""

        real_run = subprocess.run
        commands: list[list[str]] = []

        def run(command, *args, **kwargs):
            if not command or command[0] != "gh":
                return real_run(command, *args, **kwargs)
            commands.append(list(command))
            path = command[-1]
            if path not in stdout:
                return subprocess.CompletedProcess(
                    args=list(command),
                    returncode=1,
                    stdout="",
                    stderr="gh: Not Found (HTTP 404)",
                )
            return subprocess.CompletedProcess(
                args=list(command),
                returncode=0,
                stdout=stdout[path],
                stderr="",
            )

        with mock.patch.object(trust.subprocess, "run", side_effect=run):
            decision = self.authorize(transport=trust.GhApiTransport())
        return decision, commands

    # Real git smoke tests -------------------------------------------------

    def test_real_lightweight_ancestor_authorizes(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        decision = self.authorize()
        self.assertTrue(decision.authorized, decision.detail)
        self.assertEqual(decision.reason, trust.Refusal.AUTHORIZED)
        self.assertEqual(decision.facts["tag_commit"], self.git.reviewed)
        self.assertFalse(decision.facts["tag_annotated"])
        self.assertEqual(
            sorted(path.name for path in self.git.root.iterdir()), [".git"]
        )
        self.assertFalse((self.git.root / "release-tag-executed").exists())

    def test_real_annotated_ancestor_authorizes(self) -> None:
        self.git.annotated_tag(TAG, self.git.reviewed)
        decision = self.authorize()
        self.assertTrue(decision.authorized, decision.detail)
        self.assertEqual(decision.facts["tag_commit"], self.git.reviewed)
        self.assertTrue(decision.facts["tag_annotated"])
        self.assertEqual(
            sorted(path.name for path in self.git.root.iterdir()), [".git"]
        )
        self.assertFalse((self.git.root / "release-tag-executed").exists())

    def test_real_unreviewed_candidate_is_refused(self) -> None:
        self.git.lightweight_tag(TAG, self.git.unreviewed)
        event = self.event(self.git.unreviewed)
        transport = self.valid_transport(head_commit=self.git.unreviewed)
        decision = self.authorize(transport=transport, event=event)
        self.assert_refused(decision, trust.Refusal.CANDIDATE_NOT_ANCESTOR)

    def test_real_tag_retarget_is_refused(self) -> None:
        self.git.lightweight_tag(TAG, self.git.unreviewed)
        # The run still reports the reviewed commit, but the exact tag now
        # points elsewhere. Retargeting must not be rescued by head_branch.
        event = self.event(self.git.reviewed, head_branch=TAG)
        decision = self.authorize(event=event)
        self.assert_refused(decision, trust.Refusal.TAG_COMMIT_MISMATCH)

    def test_real_missing_and_ambiguous_tags_are_refused(self) -> None:
        decision = self.authorize()
        self.assert_refused(decision, trust.Refusal.TAG_MISSING)

        self.git.ambiguous_tag(TAG, self.git.reviewed, self.git.tip)
        decision = self.authorize()
        self.assert_refused(decision, trust.Refusal.TAG_AMBIGUOUS)

    def test_head_branch_is_only_a_hint(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        event = self.event(self.git.reviewed, head_branch="definitely-not-a-tag")
        self.transport.responses[trust.workflow_run_api(REPOSITORY, RUN_ID)] = (
            self.run_payload(self.git.reviewed, head_branch="main")
        )
        decision = self.authorize(event=event)
        self.assertTrue(decision.authorized, decision.detail)

    # Workflow binding -----------------------------------------------------

    def test_workflow_run_binding_dimensions(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        cases: list[tuple[str, dict[str, object], dict[str, object] | None, trust.Refusal]] = []
        event = self.event(self.git.reviewed, path=".github/workflows/other.yml")
        cases.append(
            (
                "path",
                event,
                None,
                trust.Refusal.WORKFLOW_RUN_PATH_UNTRUSTED,
            )
        )
        event = self.event(self.git.reviewed, trigger="pull_request")
        cases.append(
            ("event", event, None, trust.Refusal.WORKFLOW_RUN_NOT_PUSH)
        )
        event = self.event(self.git.reviewed, conclusion="failure")
        cases.append(
            ("conclusion", event, None, trust.Refusal.WORKFLOW_RUN_NOT_SUCCESS)
        )
        event = self.event(self.git.reviewed)
        run = self.run_payload(self.git.reviewed, run_id=RUN_ID + 1)
        cases.append(
            (
                "run id",
                event,
                {trust.workflow_run_api(REPOSITORY, RUN_ID): run},
                trust.Refusal.WORKFLOW_RUN_MISMATCH,
            )
        )
        event = self.event(self.git.reviewed)
        run = self.run_payload(self.git.reviewed, workflow_id=WORKFLOW_ID + 1)
        cases.append(
            (
                "workflow id",
                event,
                {trust.workflow_run_api(REPOSITORY, RUN_ID): run},
                trust.Refusal.WORKFLOW_RUN_MISMATCH,
            )
        )
        event = self.event(self.git.reviewed)
        run = self.run_payload(self.git.tip)
        cases.append(
            (
                "head sha",
                event,
                {trust.workflow_run_api(REPOSITORY, RUN_ID): run},
                trust.Refusal.WORKFLOW_RUN_MISMATCH,
            )
        )
        event = self.event(self.git.reviewed, repository_id=REPOSITORY_ID + 1)
        cases.append(
            (
                "repository id",
                event,
                None,
                trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            )
        )
        event = self.event(self.git.reviewed, full_name="acme/other")
        cases.append(
            (
                "repository name",
                event,
                None,
                trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            )
        )

        for label, event, overrides, expected in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                if overrides:
                    transport.responses.update(overrides)
                decision = self.authorize(transport=transport, event=event)
                self.assert_refused(decision, expected)

    def test_api_head_must_equal_the_exact_tag_commit(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        event = self.event(self.git.tip)
        transport = self.valid_transport(head_commit=self.git.tip)
        decision = self.authorize(transport=transport, event=event)
        self.assert_refused(decision, trust.Refusal.TAG_COMMIT_MISMATCH)

    # Metadata absence/unreadability --------------------------------------

    def test_absent_unreadable_and_unknown_metadata_are_fixed_enums(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        cases: list[tuple[str, str, object, trust.Refusal]] = [
            (
                "repository absent",
                trust.repository_api(REPOSITORY),
                trust.ApiResponse(404, None),
                trust.Refusal.REPOSITORY_ABSENT,
            ),
            (
                "repository unreadable",
                trust.repository_api(REPOSITORY),
                trust.ApiResponse(403, None),
                trust.Refusal.REPOSITORY_UNREADABLE,
            ),
            (
                "repository unknown",
                trust.repository_api(REPOSITORY),
                trust.ApiResponse(500, None),
                trust.Refusal.REPOSITORY_UNKNOWN,
            ),
            (
                "run absent",
                trust.workflow_run_api(REPOSITORY, RUN_ID),
                trust.ApiResponse(404, None),
                trust.Refusal.WORKFLOW_RUN_ABSENT,
            ),
            (
                "run unreadable",
                trust.workflow_run_api(REPOSITORY, RUN_ID),
                trust.ApiResponse(403, None),
                trust.Refusal.WORKFLOW_RUN_UNREADABLE,
            ),
            (
                "run unknown",
                trust.workflow_run_api(REPOSITORY, RUN_ID),
                trust.ApiResponse(500, None),
                trust.Refusal.WORKFLOW_RUN_UNKNOWN,
            ),
            (
                "branch absent",
                trust.branch_api(REPOSITORY),
                trust.ApiResponse(404, None),
                trust.Refusal.DEFAULT_BRANCH_ABSENT,
            ),
            (
                "branch unreadable",
                trust.branch_api(REPOSITORY),
                trust.ApiResponse(403, None),
                trust.Refusal.DEFAULT_BRANCH_UNREADABLE,
            ),
            (
                "protection unknown",
                trust.branch_protection_api(REPOSITORY),
                trust.ApiResponse(500, None),
                trust.Refusal.BRANCH_PROTECTION_UNKNOWN,
            ),
            (
                "rulesets unknown",
                trust.rulesets_api(REPOSITORY),
                trust.ApiResponse(500, None),
                trust.Refusal.TAG_RULES_UNKNOWN,
            ),
            (
                "environment absent",
                trust.environment_api(REPOSITORY),
                trust.ApiResponse(404, None),
                trust.Refusal.ENVIRONMENT_ABSENT,
            ),
            (
                "environment unreadable",
                trust.environment_api(REPOSITORY),
                trust.ApiResponse(403, None),
                trust.Refusal.ENVIRONMENT_UNREADABLE,
            ),
            (
                "environment secrets unreadable",
                trust.environment_secrets_api(REPOSITORY),
                trust.ApiResponse(403, None),
                trust.Refusal.SECRETS_ENVIRONMENT_UNREADABLE,
            ),
            (
                "repository secrets unknown",
                trust.repository_secrets_api(REPOSITORY),
                trust.ApiResponse(500, None),
                trust.Refusal.SECRETS_REPOSITORY_UNKNOWN,
            ),
        ]
        for label, path, response, expected in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[path] = response
                self.assert_refused(self.authorize(transport=transport), expected)

    def test_malformed_metadata_fails_closed(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        cases: list[tuple[str, str, object, trust.Refusal]] = [
            (
                "repository shape",
                trust.repository_api(REPOSITORY),
                ["not", "an", "object"],
                trust.Refusal.REPOSITORY_UNKNOWN,
            ),
            (
                "run shape",
                trust.workflow_run_api(REPOSITORY, RUN_ID),
                {"id": RUN_ID},
                trust.Refusal.WORKFLOW_RUN_UNKNOWN,
            ),
            (
                "ruleset detail shape",
                trust.ruleset_api(REPOSITORY, 7),
                {"id": 7, "target": "tag"},
                trust.Refusal.TAG_RULES_UNKNOWN,
            ),
            (
                "environment shape",
                trust.environment_api(REPOSITORY),
                {"name": trust.PRODUCTION_ENVIRONMENT},
                trust.Refusal.ENVIRONMENT_INSUFFICIENT,
            ),
            (
                "secret list shape",
                trust.environment_secrets_api(REPOSITORY),
                {"secrets": [{"value": "must-never-be-read"}]},
                trust.Refusal.SECRETS_ENVIRONMENT_UNKNOWN,
            ),
        ]
        for label, path, payload, expected in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[path] = payload
                self.assert_refused(self.authorize(transport=transport), expected)

    # Main protection ------------------------------------------------------

    def test_protected_main_required_checks_and_no_force_delete(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        base = self.valid_protection()
        cases: list[tuple[str, object, trust.Refusal]] = [
            (
                "protection absent",
                trust.ApiResponse(404, None),
                trust.Refusal.BRANCH_PROTECTION_ABSENT,
            ),
            (
                "contexts only",
                {
                    **base,
                    "required_status_checks": {
                        "strict": True,
                        "contexts": [trust.REQUIRED_STATUS_CHECK_CONTEXT],
                    },
                },
                trust.Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            ),
            (
                "force pushes",
                {**base, "allow_force_pushes": {"enabled": True}},
                trust.Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            ),
            (
                "deletions",
                {**base, "allow_deletions": {"enabled": True}},
                trust.Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            ),
            (
                "admins bypass",
                {**base, "enforce_admins": {"enabled": False}},
                trust.Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            ),
            (
                "missing force-push field",
                {
                    key: value
                    for key, value in base.items()
                    if key != "allow_force_pushes"
                },
                trust.Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            ),
        ]
        for label, payload, expected in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[trust.branch_protection_api(REPOSITORY)] = payload
                self.assert_refused(self.authorize(transport=transport), expected)

    def test_required_status_check_is_exact_and_app_bound(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        base = self.valid_protection()
        exact = {
            "context": trust.REQUIRED_STATUS_CHECK_CONTEXT,
            "app_id": trust.GITHUB_ACTIONS_APP_ID,
        }
        cases: list[tuple[str, object]] = [
            ("missing checks", {"contexts": [trust.REQUIRED_STATUS_CHECK_CONTEXT]}),
            ("empty checks", {"contexts": [], "checks": []}),
            ("renamed check", {"checks": [{**exact, "context": "ci"}]}),
            (
                "missing required check",
                {"checks": [{"context": "other", "app_id": 15368}]},
            ),
            ("any-app sentinel", {"checks": [{**exact, "app_id": -1}]}),
            ("null app", {"checks": [{**exact, "app_id": None}]}),
            ("boolean app", {"checks": [{**exact, "app_id": True}]}),
            ("other app", {"checks": [{**exact, "app_id": 12345}]}),
            (
                "missing app",
                {"checks": [{"context": trust.REQUIRED_STATUS_CHECK_CONTEXT}]},
            ),
            ("duplicate exact checks", {"checks": [exact, dict(exact)]}),
            ("malformed entry", {"checks": [trust.REQUIRED_STATUS_CHECK_CONTEXT]}),
        ]
        for label, checks in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[trust.branch_protection_api(REPOSITORY)] = {
                    **base,
                    "required_status_checks": checks,
                }
                self.assert_refused(
                    self.authorize(transport=transport),
                    trust.Refusal.BRANCH_PROTECTION_INSUFFICIENT,
                )

    def test_required_pull_request_reviews_are_fail_closed(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        base = self.valid_protection()
        valid_reviews = self.valid_reviews()
        bypass = valid_reviews["bypass_pull_request_allowances"]
        assert isinstance(bypass, dict)
        cases: list[tuple[str, object]] = [
            ("missing reviews", {k: v for k, v in base.items() if k != "required_pull_request_reviews"}),
            ("null reviews", {**base, "required_pull_request_reviews": None}),
            (
                "zero approvals",
                {
                    **base,
                    "required_pull_request_reviews": {
                        **valid_reviews,
                        "required_approving_review_count": 0,
                    },
                },
            ),
            (
                "boolean approvals",
                {
                    **base,
                    "required_pull_request_reviews": {
                        **valid_reviews,
                        "required_approving_review_count": True,
                    },
                },
            ),
            (
                "string approvals",
                {
                    **base,
                    "required_pull_request_reviews": {
                        **valid_reviews,
                        "required_approving_review_count": "1",
                    },
                },
            ),
            (
                "stale approvals kept",
                {
                    **base,
                    "required_pull_request_reviews": {
                        **valid_reviews,
                        "dismiss_stale_reviews": False,
                    },
                },
            ),
            (
                "last push not approved",
                {
                    **base,
                    "required_pull_request_reviews": {
                        **valid_reviews,
                        "require_last_push_approval": False,
                    },
                },
            ),
            (
                "missing bypass metadata",
                {
                    **base,
                    "required_pull_request_reviews": {
                        key: value
                        for key, value in valid_reviews.items()
                        if key != "bypass_pull_request_allowances"
                    },
                },
            ),
            (
                "users bypass",
                {
                    **base,
                    "required_pull_request_reviews": {
                        **valid_reviews,
                        "bypass_pull_request_allowances": {
                            **bypass,
                            "users": [{"login": "untrusted"}],
                        },
                    },
                },
            ),
            (
                "teams bypass",
                {
                    **base,
                    "required_pull_request_reviews": {
                        **valid_reviews,
                        "bypass_pull_request_allowances": {
                            **bypass,
                            "teams": [{"slug": "untrusted"}],
                        },
                    },
                },
            ),
            (
                "apps bypass",
                {
                    **base,
                    "required_pull_request_reviews": {
                        **valid_reviews,
                        "bypass_pull_request_allowances": {
                            **bypass,
                            "apps": [{"slug": "untrusted"}],
                        },
                    },
                },
            ),
            (
                "unknown bypass class",
                {
                    **base,
                    "required_pull_request_reviews": {
                        **valid_reviews,
                        "bypass_pull_request_allowances": {**bypass, "roles": []},
                    },
                },
            ),
            (
                "malformed bypass class",
                {
                    **base,
                    "required_pull_request_reviews": {
                        **valid_reviews,
                        "bypass_pull_request_allowances": {
                            **bypass,
                            "users": "nobody",
                        },
                    },
                },
            ),
        ]
        for label, payload in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[trust.branch_protection_api(REPOSITORY)] = payload
                self.assert_refused(
                    self.authorize(transport=transport),
                    trust.Refusal.BRANCH_PROTECTION_INSUFFICIENT,
                )

    def test_more_approvals_than_minimum_remain_valid(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        payload = self.valid_protection()
        reviews = self.valid_reviews()
        reviews["required_approving_review_count"] = 2
        payload["required_pull_request_reviews"] = reviews
        transport = self.valid_transport()
        transport.responses[trust.branch_protection_api(REPOSITORY)] = payload
        decision = self.authorize(transport=transport)
        self.assertTrue(decision.authorized, decision.detail)

    def test_unprotected_branch_metadata_is_refused(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        transport = self.valid_transport()
        transport.responses[trust.branch_api(REPOSITORY)] = {
            "name": "main",
            "protected": False,
            "commit": {"sha": self.git.tip},
        }
        self.assert_refused(
            self.authorize(transport=transport),
            trust.Refusal.DEFAULT_BRANCH_UNPROTECTED,
        )

    def test_default_branch_metadata_and_real_object_are_bound(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        cases: list[tuple[str, str, object, trust.Refusal]] = [
            (
                "repository default",
                trust.repository_api(REPOSITORY),
                self.repository_payload(default_branch="develop"),
                trust.Refusal.DEFAULT_BRANCH_UNTRUSTED,
            ),
            (
                "branch name",
                trust.branch_api(REPOSITORY),
                {
                    "name": "release",
                    "protected": True,
                    "commit": {"sha": self.git.tip},
                },
                trust.Refusal.DEFAULT_BRANCH_UNTRUSTED,
            ),
            (
                "branch object absent locally",
                trust.branch_api(REPOSITORY),
                {
                    "name": "main",
                    "protected": True,
                    "commit": {"sha": "f" * 40},
                },
                trust.Refusal.DEFAULT_BRANCH_OBJECT_MISSING,
            ),
        ]
        for label, path, payload, expected in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[path] = payload
                self.assert_refused(self.authorize(transport=transport), expected)

    # Tag rules ------------------------------------------------------------

    def test_active_immutable_vstar_tag_rules_without_untrusted_bypass(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        detail = copy.deepcopy(
            self.transport.responses[trust.ruleset_api(REPOSITORY, 7)]
        )
        cases: list[tuple[str, object, object, trust.Refusal]] = [
            (
                "no rulesets",
                [],
                detail,
                trust.Refusal.TAG_RULES_ABSENT,
            ),
            (
                "inactive",
                [{"id": 7, "target": "tag", "enforcement": "disabled"}],
                {**detail, "enforcement": "disabled"},
                trust.Refusal.TAG_RULES_INSUFFICIENT,
            ),
            (
                "exact tag only",
                [{"id": 7, "target": "tag", "enforcement": "active"}],
                {
                    **detail,
                    "conditions": {
                        "ref_name": {
                            "include": ["refs/tags/v1.2.3"],
                            "exclude": [],
                        }
                    },
                },
                trust.Refusal.TAG_RULES_INSUFFICIENT,
            ),
            (
                "excluded tag",
                [{"id": 7, "target": "tag", "enforcement": "active"}],
                {
                    **detail,
                    "conditions": {
                        "ref_name": {
                            "include": ["refs/tags/v*"],
                            "exclude": ["refs/tags/v1.2.3"],
                        }
                    },
                },
                trust.Refusal.TAG_RULES_INSUFFICIENT,
            ),
            (
                "missing update rule",
                [{"id": 7, "target": "tag", "enforcement": "active"}],
                {
                    **detail,
                    "rules": [
                        {"type": "deletion"},
                        {"type": "non_fast_forward"},
                    ],
                },
                trust.Refusal.TAG_RULES_INSUFFICIENT,
            ),
            (
                "untrusted integration bypass",
                [{"id": 7, "target": "tag", "enforcement": "active"}],
                {
                    **detail,
                    "bypass_actors": [
                        {
                            "actor_id": 9,
                            "actor_type": "Integration",
                            "bypass_mode": "always",
                        }
                    ],
                },
                trust.Refusal.TAG_RULES_BYPASS_UNTRUSTED,
            ),
            (
                "duplicate ruleset ids",
                [
                    {"id": 7, "target": "tag", "enforcement": "active"},
                    {"id": 7, "target": "tag", "enforcement": "active"},
                ],
                detail,
                trust.Refusal.TAG_RULES_UNKNOWN,
            ),
        ]
        for label, summaries, ruleset_detail, expected in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[trust.rulesets_api(REPOSITORY)] = summaries
                transport.responses[trust.ruleset_api(REPOSITORY, 7)] = (
                    ruleset_detail
                )
                self.assert_refused(self.authorize(transport=transport), expected)

    def test_trusted_organization_admin_bypass_remains_authorized(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        transport = self.valid_transport()
        detail = copy.deepcopy(
            transport.responses[trust.ruleset_api(REPOSITORY, 7)]
        )
        detail["bypass_actors"] = [
            {"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always"}
        ]
        transport.responses[trust.ruleset_api(REPOSITORY, 7)] = detail
        decision = self.authorize(transport=transport)
        self.assertTrue(decision.authorized, decision.detail)

    # Environment ----------------------------------------------------------

    def test_production_environment_is_default_branch_only(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        cases: list[tuple[str, object, object, trust.Refusal]] = [
            (
                "absent",
                trust.ApiResponse(404, None),
                {"branch_policies": [{"id": 1, "name": "main", "type": "branch"}]},
                trust.Refusal.ENVIRONMENT_ABSENT,
            ),
            (
                "no policy",
                {"name": "production", "deployment_branch_policy": None},
                {"branch_policies": [{"id": 1, "name": "main", "type": "branch"}]},
                trust.Refusal.ENVIRONMENT_INSUFFICIENT,
            ),
            (
                "protected branches",
                {
                    "name": "production",
                    "deployment_branch_policy": {
                        "protected_branches": True,
                        "custom_branch_policies": False,
                    },
                },
                {"branch_policies": [{"id": 1, "name": "main", "type": "branch"}]},
                trust.Refusal.ENVIRONMENT_INSUFFICIENT,
            ),
            (
                "extra branch",
                {
                    "name": "production",
                    "deployment_branch_policy": {
                        "protected_branches": False,
                        "custom_branch_policies": True,
                    },
                },
                {
                    "branch_policies": [
                        {"id": 1, "name": "main", "type": "branch"},
                        {"id": 2, "name": "release", "type": "branch"},
                    ]
                },
                trust.Refusal.BRANCH_POLICIES_INSUFFICIENT,
            ),
            (
                "wildcard",
                {
                    "name": "production",
                    "deployment_branch_policy": {
                        "protected_branches": False,
                        "custom_branch_policies": True,
                    },
                },
                {"branch_policies": [{"id": 2, "name": "*", "type": "branch"}]},
                trust.Refusal.BRANCH_POLICIES_INSUFFICIENT,
            ),
            (
                "tag policy",
                {
                    "name": "production",
                    "deployment_branch_policy": {
                        "protected_branches": False,
                        "custom_branch_policies": True,
                    },
                },
                {"branch_policies": [{"id": 2, "name": "main", "type": "tag"}]},
                trust.Refusal.BRANCH_POLICIES_INSUFFICIENT,
            ),
            (
                "truncated policy list",
                {
                    "name": "production",
                    "deployment_branch_policy": {
                        "protected_branches": False,
                        "custom_branch_policies": True,
                    },
                },
                {
                    "total_count": 2,
                    "branch_policies": [{"id": 1, "name": "main", "type": "branch"}],
                },
                trust.Refusal.BRANCH_POLICIES_UNKNOWN,
            ),
            (
                "duplicate policy ids",
                {
                    "name": "production",
                    "deployment_branch_policy": {
                        "protected_branches": False,
                        "custom_branch_policies": True,
                    },
                },
                {
                    "total_count": 2,
                    "branch_policies": [
                        {"id": 1, "name": "main", "type": "branch"},
                        {"id": 1, "name": "release", "type": "branch"},
                    ],
                },
                trust.Refusal.BRANCH_POLICIES_UNKNOWN,
            ),
            (
                "missing policy id",
                {
                    "name": "production",
                    "deployment_branch_policy": {
                        "protected_branches": False,
                        "custom_branch_policies": True,
                    },
                },
                {"branch_policies": [{"name": "main", "type": "branch"}]},
                trust.Refusal.BRANCH_POLICIES_UNKNOWN,
            ),
        ]
        for label, environment, policies, expected in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[trust.environment_api(REPOSITORY)] = environment
                transport.responses[
                    trust.environment_branch_policies_api(REPOSITORY)
                ] = policies
                self.assert_refused(self.authorize(transport=transport), expected)

    def test_branch_policies_absent_is_fixed_enum(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        transport = self.valid_transport()
        transport.responses[trust.environment_branch_policies_api(REPOSITORY)] = (
            trust.ApiResponse(404, None)
        )
        self.assert_refused(
            self.authorize(transport=transport),
            trust.Refusal.BRANCH_POLICIES_ABSENT,
        )

    # Credential scope -----------------------------------------------------

    def test_production_credentials_are_environment_only(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        cases: list[tuple[str, str, object, bool, trust.Refusal]] = [
            (
                "missing environment updater",
                trust.environment_secrets_api(REPOSITORY),
                {
                    "secrets": [
                        {"name": name}
                        for name in sorted(trust.REQUIRED_ENVIRONMENT_SECRETS)
                        if name != "MYGO_UPDATER_PRIVATE_KEY"
                    ]
                },
                False,
                trust.Refusal.SECRETS_ENVIRONMENT_MISSING,
            ),
            (
                "repository scoped updater",
                trust.repository_secrets_api(REPOSITORY),
                {
                    "secrets": [
                        {"name": "MYGO_UPDATER_PRIVATE_KEY"},
                    ]
                },
                False,
                trust.Refusal.SECRETS_REPOSITORY_LEAK,
            ),
            (
                "repository scoped optional windows certificate",
                trust.repository_secrets_api(REPOSITORY),
                {"secrets": [{"name": "WINDOWS_CERTIFICATE"}]},
                False,
                trust.Refusal.SECRETS_REPOSITORY_LEAK,
            ),
            (
                "organization scoped signing credential",
                trust.organization_secrets_api(OWNER),
                {"secrets": [{"name": "MACOS_CERTIFICATE"}]},
                True,
                trust.Refusal.SECRETS_ORGANIZATION_LEAK,
            ),
            (
                "organization secret listing absent",
                trust.organization_secrets_api(OWNER),
                trust.ApiResponse(404, None),
                True,
                trust.Refusal.SECRETS_ORGANIZATION_ABSENT,
            ),
            (
                "truncated environment secret list",
                trust.environment_secrets_api(REPOSITORY),
                {
                    "total_count": len(trust.REQUIRED_ENVIRONMENT_SECRETS) + 1,
                    "secrets": [
                        {"name": name}
                        for name in sorted(trust.REQUIRED_ENVIRONMENT_SECRETS)
                    ],
                },
                False,
                trust.Refusal.SECRETS_ENVIRONMENT_UNKNOWN,
            ),
            (
                "duplicate environment secret name",
                trust.environment_secrets_api(REPOSITORY),
                {
                    "total_count": len(trust.REQUIRED_ENVIRONMENT_SECRETS) + 1,
                    "secrets": [
                        {"name": name}
                        for name in sorted(trust.REQUIRED_ENVIRONMENT_SECRETS)
                    ]
                    + [{"name": sorted(trust.REQUIRED_ENVIRONMENT_SECRETS)[0]}],
                },
                False,
                trust.Refusal.SECRETS_ENVIRONMENT_UNKNOWN,
            ),
        ]
        for label, path, payload, organization, expected in cases:
            with self.subTest(case=label):
                transport = self.valid_transport(
                    owner_type="Organization" if organization else "User"
                )
                transport.responses[path] = payload
                self.assert_refused(self.authorize(transport=transport), expected)

    # Generic unsafe-policy fixture and read-only API surface ---------------

    def test_generic_unsafe_policy_fixture_is_refused_not_repaired(self) -> None:
        """A fabricated unsafe-policy fixture is refused, not repaired or granted."""

        self.git.lightweight_tag(TAG, self.git.reviewed)
        transport = self.valid_transport()
        transport.responses[trust.branch_protection_api(REPOSITORY)] = (
            trust.ApiResponse(404, None)
        )
        transport.responses[trust.rulesets_api(REPOSITORY)] = []
        transport.responses[trust.environment_api(REPOSITORY)] = (
            trust.ApiResponse(404, None)
        )
        transport.responses[trust.repository_secrets_api(REPOSITORY)] = {
            "secrets": [{"name": "MYGO_UPDATER_PRIVATE_KEY"}]
        }
        decision = self.authorize(transport=transport)
        self.assert_refused(decision, trust.Refusal.BRANCH_PROTECTION_ABSENT)
        self.assertNotIn("AUTHORIZE", json.dumps(decision.as_json()))
        self.assertEqual(decision.reason.value, "branch_protection_absent")

    def test_api_transport_allowlist_never_reads_secret_values_or_writes(self) -> None:
        allowed = [
            trust.repository_api(REPOSITORY),
            trust.workflow_run_api(REPOSITORY, RUN_ID),
            trust.branch_api(REPOSITORY),
            trust.branch_protection_api(REPOSITORY),
            trust.rulesets_api(REPOSITORY),
            trust.ruleset_api(REPOSITORY, 7),
            trust.environment_api(REPOSITORY),
            trust.environment_branch_policies_api(REPOSITORY),
            trust.environment_secrets_api(REPOSITORY),
            trust.repository_secrets_api(REPOSITORY),
            trust.organization_secrets_api(OWNER),
        ]
        for path in allowed:
            trust.validate_readonly_endpoint(path)
        forbidden = [
            f"{trust.environment_secrets_api(REPOSITORY).split('?', 1)[0]}/MYGO_UPDATER_PRIVATE_KEY",
            "/repos/acme/widget/actions/secrets/MYGO_UPDATER_PRIVATE_KEY",
            "/orgs/acme/actions/secrets/MACOS_CERTIFICATE",
            "/repos/acme/widget/actions/workflows/release.yml/dispatches",
            "/repos/acme/widget/git/refs",
            "/repos/acme/widget/merges",
            "/repos/acme/widget/actions/runners",
            "/repos/acme/widget/branches/main/protection/required_status_checks",
            "/repos/acme/widget/branches/main/protection/required_pull_request_reviews",
        ]
        for path in forbidden:
            with self.subTest(path=path), self.assertRaises(trust.UnsafeEndpoint):
                trust.validate_readonly_endpoint(path)

    def test_no_secret_values_are_read_or_emitted(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        decision = self.authorize()
        self.assertTrue(decision.authorized, decision.detail)
        encoded = json.dumps(decision.as_json())
        self.assertNotIn("must-never-be-read", encoded)
        for method, path in self.transport.calls:
            self.assertIn(method, ("get", "get_list"))
            self.assertNotRegex(
                path,
                r"/secrets/[^/?#]+",
                "transport must never request a secret value endpoint",
            )

    # Production transport pagination composition -------------------------

    def test_gh_pagination_composed_smoke_is_read_only(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        stdout = self.gh_fixture_stdout(owner_type="Organization")
        secret_value = "must-never-be-read"
        environment_path = trust.environment_secrets_api(REPOSITORY)
        environment_pages = json.loads(stdout[environment_path])
        environment_pages[0]["secrets"][0]["value"] = secret_value
        stdout[environment_path] = json.dumps(environment_pages)

        decision, commands = self.authorize_via_gh(stdout)

        self.assertTrue(decision.authorized, decision.detail)
        self.assertEqual(decision.reason, trust.Refusal.AUTHORIZED)
        paginated = {
            trust.rulesets_api(REPOSITORY),
            trust.environment_branch_policies_api(REPOSITORY),
            trust.environment_secrets_api(REPOSITORY),
            trust.repository_secrets_api(REPOSITORY),
            trust.organization_secrets_api(OWNER),
        }
        called = {command[-1] for command in commands}
        self.assertTrue(paginated <= called)
        self.assertTrue(commands)
        for command in commands:
            self.assertEqual(command[:4], ["gh", "api", "--method", "GET"])
            for write_verb in ("POST", "PUT", "PATCH", "DELETE"):
                self.assertNotIn(write_verb, command)
            path = command[-1]
            self.assertTrue(path.startswith("/"))
            self.assertNotRegex(path, r"/secrets/[^/?#]+")
            self.assertNotIn(secret_value, command)
            if path in paginated:
                self.assertIn("--paginate", command)
                self.assertIn("--slurp", command)
            else:
                self.assertNotIn("--paginate", command)
        self.assertNotIn(secret_value, json.dumps(decision.as_json()))

    def test_gh_pagination_accepts_zero_item_wrapper_pages(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        stdout = self.gh_fixture_stdout()
        stdout[trust.repository_secrets_api(REPOSITORY)] = json.dumps(
            [{"total_count": 0, "secrets": []}]
        )
        decision, _ = self.authorize_via_gh(stdout)
        self.assertTrue(decision.authorized, decision.detail)

        stdout = self.gh_fixture_stdout()
        stdout[trust.environment_branch_policies_api(REPOSITORY)] = json.dumps(
            [{"total_count": 0, "branch_policies": []}]
        )
        decision, _ = self.authorize_via_gh(stdout)
        self.assert_refused(
            decision, trust.Refusal.BRANCH_POLICIES_INSUFFICIENT
        )

    def test_gh_pagination_flattens_multi_page_secret_listing(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        names = [f"OTHER_SECRET_{index:03d}" for index in range(101)]
        items = [{"name": name} for name in names]
        pages = [
            {"total_count": len(items), "secrets": items[:100]},
            {"total_count": len(items), "secrets": items[100:]},
        ]
        stdout = self.gh_fixture_stdout()
        repository_path = trust.repository_secrets_api(REPOSITORY)
        stdout[repository_path] = json.dumps(pages)

        decision, commands = self.authorize_via_gh(stdout)

        self.assertTrue(decision.authorized, decision.detail)
        repository_commands = [
            command for command in commands if command[-1] == repository_path
        ]
        self.assertEqual(len(repository_commands), 1)
        self.assertIn("--paginate", repository_commands[0])
        self.assertIn("--slurp", repository_commands[0])

    def test_gh_pagination_incomplete_changed_and_extra_pages_refuse(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        items = [{"name": f"OTHER_SECRET_{index:03d}"} for index in range(101)]
        repository_path = trust.repository_secrets_api(REPOSITORY)
        cases = [
            (
                "missing later page",
                [{"total_count": len(items), "secrets": items[:100]}],
            ),
            (
                "changed total",
                [
                    {"total_count": len(items), "secrets": items[:100]},
                    {"total_count": len(items) + 1, "secrets": items[100:]},
                ],
            ),
            (
                "extra page",
                [
                    {
                        "total_count": 1,
                        "secrets": [{"name": "OTHER_SECRET_ONLY"}],
                    },
                    {"total_count": 1, "secrets": []},
                ],
            ),
        ]
        for label, pages in cases:
            with self.subTest(case=label):
                stdout = self.gh_fixture_stdout()
                stdout[repository_path] = json.dumps(pages)
                decision, _ = self.authorize_via_gh(stdout)
                self.assert_refused(
                    decision, trust.Refusal.SECRETS_REPOSITORY_UNKNOWN
                )

    def test_gh_pagination_malformed_wrapper_pages_refuse(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        branch_path = trust.environment_branch_policies_api(REPOSITORY)
        repository_path = trust.repository_secrets_api(REPOSITORY)
        cases = [
            (
                "branch wrapper missing key",
                branch_path,
                [{"total_count": 1}],
                trust.Refusal.BRANCH_POLICIES_UNKNOWN,
            ),
            (
                "branch wrapper wrong key",
                branch_path,
                [
                    {
                        "total_count": 1,
                        "secrets": [{"name": "main"}],
                    }
                ],
                trust.Refusal.BRANCH_POLICIES_UNKNOWN,
            ),
            (
                "secret wrapper extra key",
                repository_path,
                [{"total_count": 0, "secrets": [], "extra": []}],
                trust.Refusal.SECRETS_REPOSITORY_UNKNOWN,
            ),
            (
                "secret wrapper array page",
                repository_path,
                [[]],
                trust.Refusal.SECRETS_REPOSITORY_UNKNOWN,
            ),
            (
                "secret wrapper boolean total",
                repository_path,
                [{"total_count": True, "secrets": []}],
                trust.Refusal.SECRETS_REPOSITORY_UNKNOWN,
            ),
            (
                "secret wrapper total below item count",
                repository_path,
                [
                    {
                        "total_count": 0,
                        "secrets": [{"name": "OTHER_SECRET_ONLY"}],
                    }
                ],
                trust.Refusal.SECRETS_REPOSITORY_UNKNOWN,
            ),
        ]
        for label, path, pages, expected in cases:
            with self.subTest(case=label):
                stdout = self.gh_fixture_stdout()
                stdout[path] = json.dumps(pages)
                decision, _ = self.authorize_via_gh(stdout)
                self.assert_refused(decision, expected)

    def test_gh_pagination_preserves_array_ruleset_pages(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        rulesets_path = trust.rulesets_api(REPOSITORY)
        stdout = self.gh_fixture_stdout()
        stdout[rulesets_path] = json.dumps(
            [
                [{"id": 7, "target": "tag", "enforcement": "active"}],
                [{"id": 8, "target": "branch", "enforcement": "active"}],
            ]
        )
        stdout[trust.ruleset_api(REPOSITORY, 8)] = json.dumps(
            {"id": 8, "target": "branch", "enforcement": "active"}
        )

        decision, commands = self.authorize_via_gh(stdout)

        self.assertTrue(decision.authorized, decision.detail)
        ruleset_commands = [
            command for command in commands if command[-1] == rulesets_path
        ]
        self.assertEqual(len(ruleset_commands), 1)
        self.assertIn("--paginate", ruleset_commands[0])
        self.assertIn("--slurp", ruleset_commands[0])

        stdout = self.gh_fixture_stdout()
        stdout[rulesets_path] = json.dumps(
            [
                {
                    "total_count": 1,
                    "rulesets": [
                        {"id": 7, "target": "tag", "enforcement": "active"}
                    ],
                }
            ]
        )
        decision, _ = self.authorize_via_gh(stdout)
        self.assert_refused(decision, trust.Refusal.TAG_RULES_UNKNOWN)

    def test_gh_pagination_accepts_distinct_multi_page_ruleset_ids(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        rulesets_path = trust.rulesets_api(REPOSITORY)
        branch_summaries = [
            {"id": 1000 + index, "target": "branch", "enforcement": "active"}
            for index in range(100)
        ]
        stdout = self.gh_fixture_stdout()
        stdout[rulesets_path] = json.dumps(
            [
                branch_summaries,
                [{"id": 7, "target": "tag", "enforcement": "active"}],
            ]
        )
        for summary in branch_summaries:
            stdout[trust.ruleset_api(REPOSITORY, summary["id"])] = json.dumps(
                {
                    "id": summary["id"],
                    "target": "branch",
                    "enforcement": "active",
                }
            )

        decision, _ = self.authorize_via_gh(stdout)

        self.assertTrue(decision.authorized, decision.detail)

    def test_gh_pagination_rejects_duplicate_ruleset_pages(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        rulesets_path = trust.rulesets_api(REPOSITORY)
        duplicate_id = 987654
        cases = [
            (
                "duplicate across pages",
                [
                    [{"id": duplicate_id, "target": "tag", "enforcement": "active"}],
                    [{"id": duplicate_id, "target": "tag", "enforcement": "active"}],
                ],
            ),
            (
                "duplicate in one page",
                [
                    [
                        {
                            "id": duplicate_id,
                            "target": "tag",
                            "enforcement": "active",
                        },
                        {
                            "id": duplicate_id,
                            "target": "branch",
                            "enforcement": "active",
                        },
                    ]
                ],
            ),
        ]
        for label, pages in cases:
            with self.subTest(case=label):
                stdout = self.gh_fixture_stdout()
                stdout[rulesets_path] = json.dumps(pages)
                decision, _ = self.authorize_via_gh(stdout)
                self.assert_refused(decision, trust.Refusal.TAG_RULES_UNKNOWN)
                self.assertNotIn(
                    str(duplicate_id), json.dumps(decision.as_json())
                )

    def test_gh_pagination_rejects_duplicate_wrapped_rows(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)

        secret_name = "PRIVATE_DUPLICATE_SECRET_NAME"
        repository_path = trust.repository_secrets_api(REPOSITORY)
        stdout = self.gh_fixture_stdout()
        stdout[repository_path] = json.dumps(
            [
                {
                    "total_count": 2,
                    "secrets": [{"name": secret_name}],
                },
                {
                    "total_count": 2,
                    "secrets": [{"name": secret_name}],
                },
            ]
        )
        decision, _ = self.authorize_via_gh(stdout)
        self.assert_refused(decision, trust.Refusal.SECRETS_REPOSITORY_UNKNOWN)
        self.assertNotIn(secret_name, json.dumps(decision.as_json()))

        duplicate_policy_id = 987655
        branch_path = trust.environment_branch_policies_api(REPOSITORY)
        stdout = self.gh_fixture_stdout()
        stdout[branch_path] = json.dumps(
            [
                {
                    "total_count": 2,
                    "branch_policies": [
                        {
                            "id": duplicate_policy_id,
                            "name": "main",
                            "type": "branch",
                        },
                        {
                            "id": duplicate_policy_id,
                            "name": "release",
                            "type": "branch",
                        },
                    ],
                }
            ]
        )
        decision, _ = self.authorize_via_gh(stdout)
        self.assert_refused(decision, trust.Refusal.BRANCH_POLICIES_UNKNOWN)
        self.assertNotIn(str(duplicate_policy_id), json.dumps(decision.as_json()))

    def test_production_transport_rejects_duplicate_paginated_identities(self) -> None:
        duplicate_id = 987656
        secret_name = "PRIVATE_DUPLICATE_SECRET_NAME"
        cases = [
            (
                trust.rulesets_api(REPOSITORY),
                [
                    [{"id": duplicate_id}],
                    [{"id": duplicate_id}],
                ],
                str(duplicate_id),
            ),
            (
                trust.environment_branch_policies_api(REPOSITORY),
                [
                    {
                        "total_count": 2,
                        "branch_policies": [
                            {"id": duplicate_id, "name": "main", "type": "branch"},
                            {"id": duplicate_id, "name": "main", "type": "branch"},
                        ],
                    }
                ],
                str(duplicate_id),
            ),
            (
                trust.repository_secrets_api(REPOSITORY),
                [
                    {
                        "total_count": 2,
                        "secrets": [
                            {"name": secret_name},
                            {"name": secret_name},
                        ],
                    }
                ],
                secret_name,
            ),
        ]
        for path, pages, private_value in cases:
            with self.subTest(path=path):
                completed = subprocess.CompletedProcess(
                    args=["gh"],
                    returncode=0,
                    stdout=json.dumps(pages),
                    stderr="",
                )
                with mock.patch.object(
                    trust.subprocess, "run", return_value=completed
                ):
                    with self.assertRaises(trust.ApiTransportError) as caught:
                        trust.GhApiTransport().get_list(path)
                self.assertNotIn(private_value, caught.exception.detail)

    def test_production_transport_issues_only_allowlisted_get_commands(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["gh"], returncode=0, stdout='{"id": 7}', stderr=""
        )
        with mock.patch.object(trust.subprocess, "run", return_value=completed) as run:
            response = trust.GhApiTransport().get(
                trust.ruleset_api(REPOSITORY, 7)
            )
        self.assertEqual(response, trust.ApiResponse(200, {"id": 7}))
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["gh", "api", "--method", "GET"])
        self.assertNotIn("POST", command)
        self.assertEqual(command[-1], trust.ruleset_api(REPOSITORY, 7))
        for value in command:
            self.assertNotRegex(value, r"/secrets/[^/?#]+")

        paged = subprocess.CompletedProcess(
            args=["gh"], returncode=0, stdout='[[{"id": 7}]]', stderr=""
        )
        with mock.patch.object(trust.subprocess, "run", return_value=paged) as run:
            response = trust.GhApiTransport().get_list(
                trust.rulesets_api(REPOSITORY)
            )
        self.assertEqual(response, trust.ApiResponse(200, [{"id": 7}]))
        command = run.call_args.args[0]
        self.assertIn("--paginate", command)
        self.assertIn("--slurp", command)

    def test_production_transport_maps_http_errors_without_body_text(self) -> None:
        refusal = subprocess.CompletedProcess(
            args=["gh"],
            returncode=1,
            stdout="",
            stderr="gh: Not Found (HTTP 404)",
        )
        with mock.patch.object(trust.subprocess, "run", return_value=refusal):
            with self.assertRaises(trust.ApiTransportError) as caught:
                trust.GhApiTransport().get(trust.repository_api(REPOSITORY))
        self.assertEqual(caught.exception.status, 404)
        self.assertNotIn("Not Found", caught.exception.detail)

    def test_invalid_path_arguments_use_the_fixed_enum(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        decision = trust.authorize_desktop_release(
            event=self.event(self.git.reviewed),
            repository=REPOSITORY,
            tag=TAG,
            git_repo=None,  # type: ignore[arg-type]
            transport=self.transport,
        )
        self.assert_refused(decision, trust.Refusal.ARGUMENT_INVALID)

    def test_cli_emits_fixed_enum_and_refuses_without_policy(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        event_file = self.git.root / "event.json"
        event_file.write_text(
            json.dumps(self.event(self.git.reviewed)), encoding="utf-8"
        )
        transport = self.valid_transport()
        transport.responses[trust.branch_protection_api(REPOSITORY)] = (
            trust.ApiResponse(404, None)
        )
        output = io.StringIO()
        with mock.patch.object(
            trust, "GhApiTransport", return_value=transport
        ), redirect_stdout(output):
            code = trust.main(
                [
                    "--event",
                    str(event_file),
                    "--repository",
                    REPOSITORY,
                    "--tag",
                    TAG,
                    "--git-repo",
                    str(self.git.root),
                    "--json",
                ]
            )
        self.assertEqual(code, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["decision"], "REFUSE")
        self.assertEqual(payload["reason"], "branch_protection_absent")


if __name__ == "__main__":
    unittest.main()
