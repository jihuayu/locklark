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
import desktop_release_routing as routing  # noqa: E402


REPOSITORY = "acme/widget"
TAG = "v1.2.3"
RUN_ID = 123
WORKFLOW_ID = 456
REPOSITORY_ID = 100
OWNER_ID = 200
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
        actor_id: object = OWNER_ID,
        triggering_actor_id: object = OWNER_ID,
        actor_login: object = OWNER,
        actor_type: object = "User",
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
            "actor": {
                "id": actor_id,
                "login": actor_login,
                "type": actor_type,
            },
            "triggering_actor": {
                "id": triggering_actor_id,
                "login": actor_login,
                "type": actor_type,
            },
        }

    def repository_payload(
        self, *, owner_type: str = "User", default_branch: str = "main"
    ) -> dict[str, object]:
        return {
            "id": REPOSITORY_ID,
            "full_name": REPOSITORY,
            "default_branch": default_branch,
            "owner": {"id": OWNER_ID, "login": OWNER, "type": owner_type},
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

    def classic_protection_without_bypass(self) -> dict[str, object]:
        protection = self.valid_protection()
        reviews = dict(protection["required_pull_request_reviews"])  # type: ignore[arg-type]
        reviews.pop("bypass_pull_request_allowances", None)
        protection["required_pull_request_reviews"] = reviews
        return protection

    def valid_branch_ruleset(
        self,
        *,
        ruleset_id: int = 11,
        review_count: int = 1,
        source: str = REPOSITORY,
        source_type: str = "Repository",
        target: str = "branch",
        enforcement: str = "active",
    ) -> dict[str, object]:
        return {
            "id": ruleset_id,
            "source_type": source_type,
            "source": source,
            "target": target,
            "enforcement": enforcement,
            "conditions": {
                "ref_name": {
                    "include": [f"refs/heads/{trust.DEFAULT_BRANCH}"],
                    "exclude": [],
                }
            },
            "bypass_actors": [],
            "rules": [
                {
                    "type": "pull_request",
                    "parameters": {
                        "required_approving_review_count": review_count,
                        "dismiss_stale_reviews_on_push": True,
                        "require_last_push_approval": True,
                    },
                }
            ],
        }

    def install_branch_rulesets(
        self,
        transport: FakeTransport,
        details: list[dict[str, object]],
        *,
        summaries: list[dict[str, object]] | None = None,
        detail_ids: list[int] | None = None,
    ) -> None:
        if summaries is None:
            summaries = [{"id": detail["id"]} for detail in details]
        if detail_ids is None:
            detail_ids = [int(detail["id"]) for detail in details]
        transport.responses[trust.branch_rulesets_api(REPOSITORY)] = summaries
        for detail_id, detail in zip(detail_ids, details):
            transport.responses[trust.ruleset_api(REPOSITORY, detail_id)] = detail

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
            trust.branch_rulesets_api(REPOSITORY),
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

    def dispatch_event(
        self,
        *,
        action: str = "desktop-release",
        tag: str = TAG,
        payload: object | None = None,
        repository_id: int = REPOSITORY_ID,
        full_name: str = REPOSITORY,
        sender_id: int = OWNER_ID,
        sender_type: str = "User",
        branch: object = "main",
    ) -> dict[str, object]:
        event: dict[str, object] = {
            "action": action,
            "client_payload": {"tag": tag} if payload is None else payload,
            "repository": {"id": repository_id, "full_name": full_name},
            "sender": {"id": sender_id, "login": OWNER, "type": sender_type},
        }
        if branch is not None:
            event["branch"] = branch
        return event

    def dispatch_run_payload(
        self,
        *,
        run_id: int = RUN_ID,
        run_attempt: int = 1,
        event: str = "repository_dispatch",
        status: str = "in_progress",
        conclusion: object = None,
        head_branch: str = "main",
        head_sha: str | None = None,
        path: str = routing.DESKTOP_RELEASE_WORKFLOW_PATH,
        repository_id: int = REPOSITORY_ID,
        full_name: str = REPOSITORY,
        head_repository_id: int = REPOSITORY_ID,
        head_full_name: str = REPOSITORY,
        actor_id: int = OWNER_ID,
        actor_type: str = "User",
        triggering_actor_id: int = OWNER_ID,
        triggering_actor_type: str = "User",
    ) -> dict[str, object]:
        if head_sha is None:
            head_sha = self.git.tip
        return {
            "id": run_id,
            "run_attempt": run_attempt,
            "event": event,
            "status": status,
            "conclusion": conclusion,
            "head_branch": head_branch,
            "head_sha": head_sha,
            "path": path,
            "repository": {"id": repository_id, "full_name": full_name},
            "head_repository": {
                "id": head_repository_id,
                "full_name": head_full_name,
            },
            "actor": {"id": actor_id, "type": actor_type},
            "triggering_actor": {
                "id": triggering_actor_id,
                "type": triggering_actor_type,
            },
        }

    def dispatch_binding(self, **overrides: object) -> dict[str, object]:
        binding: dict[str, object] = {
            "run_id": str(RUN_ID),
            "run_attempt": "1",
            "sha": self.git.tip,
            "workflow_sha": self.git.tip,
        }
        binding.update(overrides)
        return binding

    def dispatch_decision(
        self,
        *,
        event: object | None = None,
        run: object | None = None,
        binding: dict[str, object] | None = None,
        transport: FakeTransport | None = None,
    ) -> trust.Decision:
        if event is None:
            event = self.dispatch_event()
        if run is None:
            run = self.dispatch_run_payload()
        if binding is None:
            binding = self.dispatch_binding()
        if transport is None:
            transport = self.valid_transport()
        transport.responses[
            trust.workflow_run_api(REPOSITORY, int(binding["run_id"]))
        ] = run
        return routing.authorize_desktop_release_dispatch(
            event=event,
            repository=REPOSITORY,
            git_repo=self.git.root,
            run_id=binding["run_id"],
            run_attempt=binding["run_attempt"],
            sha=binding["sha"],
            workflow_sha=binding["workflow_sha"],
            transport=transport,
        )

    def authorize_dispatch_via_gh(
        self,
        stdout: dict[str, str],
        *,
        event: object | None = None,
        binding: dict[str, object] | None = None,
    ) -> tuple[trust.Decision, list[list[str]]]:
        if event is None:
            event = self.dispatch_event()
        if binding is None:
            binding = self.dispatch_binding()
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
            decision = routing.authorize_desktop_release_dispatch(
                event=event,
                repository=REPOSITORY,
                git_repo=self.git.root,
                run_id=binding["run_id"],
                run_attempt=binding["run_attempt"],
                sha=binding["sha"],
                workflow_sha=binding["workflow_sha"],
                transport=trust.GhApiTransport(),
            )
        return decision, commands

    # repository_dispatch routing ------------------------------------------

    def test_dispatch_real_git_gh_transport_smoke(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        run_path = trust.workflow_run_api(REPOSITORY, RUN_ID)
        stdout = self.gh_fixture_stdout()
        stdout[run_path] = json.dumps(
            self.dispatch_run_payload(
                path=routing.DESKTOP_RELEASE_WORKFLOW_PATH + "@refs/heads/main"
            )
        )
        decision, commands = self.authorize_dispatch_via_gh(stdout)
        self.assertTrue(decision.authorized, decision.detail)
        self.assertEqual(decision.reason, trust.Refusal.AUTHORIZED)
        self.assertIn(run_path, {command[-1] for command in commands})
        for command in commands:
            self.assertEqual(command[:4], ["gh", "api", "--method", "GET"])
            for write_verb in ("POST", "PUT", "PATCH", "DELETE"):
                self.assertNotIn(write_verb, command)

        bad = dict(stdout)
        bad[run_path] = json.dumps(
            self.dispatch_run_payload(
                path=routing.DESKTOP_RELEASE_WORKFLOW_PATH + "@v1.2.3"
            )
        )
        decision, _ = self.authorize_dispatch_via_gh(bad)
        self.assert_refused(
            decision, trust.Refusal.WORKFLOW_RUN_PATH_UNTRUSTED
        )

    def test_dispatch_accepts_allowed_workflow_path_suffixes(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        for suffix in ("", "@main", "@refs/heads/main"):
            with self.subTest(suffix=suffix):
                run = self.dispatch_run_payload(
                    path=routing.DESKTOP_RELEASE_WORKFLOW_PATH + suffix
                )
                decision = self.dispatch_decision(run=run)
                self.assertTrue(decision.authorized, decision.detail)

    def test_dispatch_rejects_event_run_and_identity_mismatches(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        cases: list[
            tuple[
                str,
                object,
                object,
                dict[str, object],
                trust.Refusal,
            ]
        ] = []

        def add(
            label: str,
            expected: trust.Refusal,
            *,
            event: object | None = None,
            run: object | None = None,
            binding: dict[str, object] | None = None,
        ) -> None:
            cases.append(
                (
                    label,
                    event if event is not None else self.dispatch_event(),
                    run if run is not None else self.dispatch_run_payload(),
                    binding if binding is not None else self.dispatch_binding(),
                    expected,
                )
            )

        event = self.dispatch_event()
        event["action"] = "other"
        add("wrong action", trust.Refusal.EVENT_INVALID, event=event)

        event = self.dispatch_event()
        event["client_payload"] = {"tag": TAG, "extra": "override"}
        add("extra payload key", trust.Refusal.EVENT_INVALID, event=event)

        event = self.dispatch_event()
        event["client_payload"] = {}
        add("missing payload tag", trust.Refusal.EVENT_INVALID, event=event)

        event = self.dispatch_event()
        event["client_payload"] = None
        add("malformed payload", trust.Refusal.EVENT_INVALID, event=event)

        event = self.dispatch_event()
        event["client_payload"] = {"tag": 123}
        add("non-string tag", trust.Refusal.TAG_INVALID, event=event)

        event = self.dispatch_event(branch="develop")
        add(
            "non-default event branch",
            trust.Refusal.DEFAULT_BRANCH_UNTRUSTED,
            event=event,
        )

        event = self.dispatch_event(repository_id=REPOSITORY_ID + 1)
        add(
            "event repository id",
            trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            event=event,
        )

        event = self.dispatch_event(full_name="other/repository")
        add(
            "event repository name",
            trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            event=event,
        )

        event = self.dispatch_event(sender_type="Organization")
        add(
            "organization sender",
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            event=event,
        )

        event = self.dispatch_event(sender_id=OWNER_ID + 1)
        add(
            "wrong sender id",
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            event=event,
        )

        event = self.dispatch_event(sender_id=True)
        add(
            "boolean sender id",
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            event=event,
        )

        run = self.dispatch_run_payload(run_id=RUN_ID + 1)
        add("wrong canonical run id", trust.Refusal.WORKFLOW_RUN_MISMATCH, run=run)

        run = self.dispatch_run_payload(run_id=True)
        add(
            "boolean canonical run id",
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            run=run,
        )

        run = self.dispatch_run_payload(run_attempt=2)
        add(
            "wrong canonical attempt",
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            run=run,
        )

        run = self.dispatch_run_payload(run_attempt=True)
        add(
            "boolean canonical attempt",
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            run=run,
        )

        run = self.dispatch_run_payload(event="push")
        add(
            "wrong canonical event",
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            run=run,
        )

        run = self.dispatch_run_payload(status="completed")
        add(
            "wrong canonical status",
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            run=run,
        )

        run = self.dispatch_run_payload(conclusion="success")
        add(
            "non-null conclusion",
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            run=run,
        )

        run = self.dispatch_run_payload(head_branch="develop")
        add(
            "wrong head branch",
            trust.Refusal.DEFAULT_BRANCH_UNTRUSTED,
            run=run,
        )

        for path in (
            routing.DESKTOP_RELEASE_WORKFLOW_PATH + "@v1.2.3",
            routing.DESKTOP_RELEASE_WORKFLOW_PATH + "@refs/tags/v1.2.3",
            routing.DESKTOP_RELEASE_WORKFLOW_PATH + "@feature",
            ".github/workflows/release.yml",
        ):
            run = self.dispatch_run_payload(path=path)
            add(
                "wrong workflow path",
                trust.Refusal.WORKFLOW_RUN_PATH_UNTRUSTED,
                run=run,
            )

        run = self.dispatch_run_payload(head_sha=self.git.unreviewed)
        add(
            "wrong source SHA",
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            run=run,
        )

        run = self.dispatch_run_payload(head_sha="ABC")
        add(
            "malformed source SHA",
            trust.Refusal.WORKFLOW_RUN_HEAD_SHA_INVALID,
            run=run,
        )

        run = self.dispatch_run_payload(repository_id=REPOSITORY_ID + 1)
        add(
            "run repository id",
            trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            run=run,
        )

        run = self.dispatch_run_payload(full_name="other/repository")
        add(
            "run repository name",
            trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            run=run,
        )

        run = self.dispatch_run_payload(head_repository_id=REPOSITORY_ID + 1)
        add(
            "fork head repository id",
            trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            run=run,
        )

        run = self.dispatch_run_payload(head_full_name="fork/repository")
        add(
            "fork head repository name",
            trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            run=run,
        )

        run = self.dispatch_run_payload(actor_id=OWNER_ID + 1)
        add(
            "wrong actor id",
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            run=run,
        )

        run = self.dispatch_run_payload(actor_id=True)
        add(
            "boolean actor id",
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            run=run,
        )

        run = self.dispatch_run_payload(actor_type="Bot")
        add(
            "non-user actor",
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            run=run,
        )

        run = self.dispatch_run_payload(triggering_actor_id=OWNER_ID + 1)
        add(
            "wrong triggering actor id",
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            run=run,
        )

        run = self.dispatch_run_payload(triggering_actor_type="Bot")
        add(
            "non-user triggering actor",
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            run=run,
        )

        binding = self.dispatch_binding(sha=self.git.unreviewed)
        add(
            "trusted server SHA mismatch",
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            binding=binding,
        )

        binding = self.dispatch_binding(workflow_sha=self.git.unreviewed)
        add(
            "trusted workflow SHA mismatch",
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            binding=binding,
        )

        for label, event, run, binding, expected in cases:
            with self.subTest(case=label):
                decision = self.dispatch_decision(
                    event=event, run=run, binding=binding
                )
                self.assert_refused(decision, expected)

        invalid_bindings: list[tuple[str, dict[str, object]]] = [
            ("zero run id", self.dispatch_binding(run_id="0")),
            ("boolean attempt", self.dispatch_binding(run_attempt="true")),
            ("short server SHA", self.dispatch_binding(sha="abc")),
            (
                "uppercase workflow SHA",
                self.dispatch_binding(workflow_sha="A" * 40),
            ),
        ]
        for label, binding in invalid_bindings:
            with self.subTest(case=label):
                decision = routing.authorize_desktop_release_dispatch(
                    event=self.dispatch_event(),
                    repository=REPOSITORY,
                    git_repo=self.git.root,
                    run_id=binding["run_id"],
                    run_attempt=binding["run_attempt"],
                    sha=binding["sha"],
                    workflow_sha=binding["workflow_sha"],
                    transport=self.valid_transport(),
                )
                self.assert_refused(decision, trust.Refusal.ARGUMENT_INVALID)

    def test_dispatch_rejects_tag_ancestry_and_policy_failures(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        self.git.delete_tag(TAG)
        self.assert_refused(self.dispatch_decision(), trust.Refusal.TAG_MISSING)

        self.git.lightweight_tag(TAG, self.git.unreviewed)
        self.assert_refused(
            self.dispatch_decision(), trust.Refusal.CANDIDATE_NOT_ANCESTOR
        )
        self.git.lightweight_tag(TAG, self.git.reviewed)

        binding = self.dispatch_binding(
            sha=self.git.unreviewed, workflow_sha=self.git.unreviewed
        )
        run = self.dispatch_run_payload(head_sha=self.git.unreviewed)
        self.assert_refused(
            self.dispatch_decision(run=run, binding=binding),
            trust.Refusal.CANDIDATE_NOT_ANCESTOR,
        )

        missing_sha = "f" * 40
        binding = self.dispatch_binding(sha=missing_sha, workflow_sha=missing_sha)
        run = self.dispatch_run_payload(head_sha=missing_sha)
        self.assert_refused(
            self.dispatch_decision(run=run, binding=binding),
            trust.Refusal.WORKFLOW_OBJECT_MISSING,
        )

        transport = self.valid_transport()
        transport.responses[trust.branch_protection_api(REPOSITORY)] = (
            trust.ApiResponse(500, None)
        )
        self.assert_refused(
            self.dispatch_decision(transport=transport),
            trust.Refusal.BRANCH_PROTECTION_UNKNOWN,
        )

        transport = self.valid_transport()
        transport.responses[trust.branch_protection_api(REPOSITORY)] = (
            trust.ApiResponse(403, None)
        )
        self.assert_refused(
            self.dispatch_decision(transport=transport),
            trust.Refusal.BRANCH_PROTECTION_UNREADABLE,
        )

        transport = self.valid_transport()
        transport.responses[trust.workflow_run_api(REPOSITORY, RUN_ID)] = (
            trust.ApiResponse(403, None)
        )
        binding = self.dispatch_binding()
        decision = routing.authorize_desktop_release_dispatch(
            event=self.dispatch_event(),
            repository=REPOSITORY,
            git_repo=self.git.root,
            run_id=binding["run_id"],
            run_attempt=binding["run_attempt"],
            sha=binding["sha"],
            workflow_sha=binding["workflow_sha"],
            transport=transport,
        )
        self.assert_refused(decision, trust.Refusal.WORKFLOW_RUN_UNREADABLE)

    def test_dispatch_outputs_and_refusal_do_not_write(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        decision = self.dispatch_decision()
        self.assertTrue(decision.authorized, decision.detail)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            routing.write_github_output(output, decision.facts)
            self.assertEqual(
                output.read_text(encoding="utf-8").splitlines(),
                [
                    f"tag={TAG}",
                    f"commit={self.git.reviewed}",
                    "version=1.2.3",
                    "prerelease=false",
                ],
            )

            refusal_output = root / "refusal-output"
            refusal_output.write_text("sentinel\n", encoding="utf-8")
            event_path = root / "refusal-event.json"
            event_path.write_text(
                json.dumps(self.dispatch_event(action="other")),
                encoding="utf-8",
            )
            code = routing.main(
                [
                    "--event",
                    str(event_path),
                    "--repository",
                    REPOSITORY,
                    "--git-repo",
                    str(self.git.root),
                    "--run-id",
                    str(RUN_ID),
                    "--run-attempt",
                    "1",
                    "--sha",
                    self.git.tip,
                    "--workflow-sha",
                    self.git.tip,
                    "--github-output",
                    str(refusal_output),
                ],
                transport=self.valid_transport(),
            )
            self.assertEqual(code, 1)
            self.assertEqual(
                refusal_output.read_text(encoding="utf-8"), "sentinel\n"
            )

            accepted_output = root / "accepted-output"
            accepted_event = root / "accepted-event.json"
            accepted_event.write_text(
                json.dumps(self.dispatch_event()), encoding="utf-8"
            )
            transport = self.valid_transport()
            transport.responses[trust.workflow_run_api(REPOSITORY, RUN_ID)] = (
                self.dispatch_run_payload()
            )
            code = routing.main(
                [
                    "--event",
                    str(accepted_event),
                    "--repository",
                    REPOSITORY,
                    "--git-repo",
                    str(self.git.root),
                    "--run-id",
                    str(RUN_ID),
                    "--run-attempt",
                    "1",
                    "--sha",
                    self.git.tip,
                    "--workflow-sha",
                    self.git.tip,
                    "--github-output",
                    str(accepted_output),
                ],
                transport=transport,
            )
            self.assertEqual(code, 0)
            self.assertEqual(
                accepted_output.read_text(encoding="utf-8").splitlines(),
                [
                    f"tag={TAG}",
                    f"commit={self.git.reviewed}",
                    "version=1.2.3",
                    "prerelease=false",
                ],
            )

            for index, (release_tag, expected_version, expected_prerelease) in enumerate(
                (
                    ("v1.2.3+build-1", "1.2.3+build-1", "false"),
                    ("v1.2.3-rc.1", "1.2.3-rc.1", "true"),
                )
            ):
                with self.subTest(release_tag=release_tag):
                    self.git.lightweight_tag(release_tag, self.git.reviewed)
                    variant = self.dispatch_decision(
                        event=self.dispatch_event(tag=release_tag)
                    )
                    self.assertTrue(variant.authorized, variant.detail)
                    variant_output = root / f"variant-{index}"
                    routing.write_github_output(variant_output, variant.facts)
                    self.assertEqual(
                        variant_output.read_text(
                            encoding="utf-8"
                        ).splitlines(),
                        [
                            f"tag={release_tag}",
                            f"commit={self.git.reviewed}",
                            f"version={expected_version}",
                            f"prerelease={expected_prerelease}",
                        ],
                    )

    def test_dispatch_output_injection_and_diagnostics_are_safe(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        injected = TAG + "\nleak=true"
        decision = self.dispatch_decision(
            event=self.dispatch_event(tag=injected)
        )
        self.assert_refused(decision, trust.Refusal.TAG_INVALID)
        for value in (TAG, REPOSITORY, OWNER):
            self.assertNotIn(value, decision.detail)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.write_text("sentinel\n", encoding="utf-8")
            with self.assertRaises(trust.ReleaseRefusal):
                routing.write_github_output(
                    output,
                    {
                        "tag": injected,
                        "tag_commit": self.git.reviewed,
                        "version": "1.2.3",
                        "prerelease": False,
                    },
                )
            self.assertEqual(output.read_text(encoding="utf-8"), "sentinel\n")

        transport = self.valid_transport()
        secret_name = next(iter(trust.PRODUCTION_SECRETS))
        transport.responses[trust.repository_secrets_api(REPOSITORY)] = {
            "total_count": 1,
            "secrets": [{"name": secret_name}],
        }
        decision = self.dispatch_decision(transport=transport)
        self.assert_refused(decision, trust.Refusal.SECRETS_REPOSITORY_LEAK)
        for value in (TAG, REPOSITORY, OWNER, secret_name):
            self.assertNotIn(value, decision.detail)

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

    # Release initiator policy ---------------------------------------------

    def test_composed_personal_owner_tag_signal_and_owner_rerun_authorize(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        decision = self.authorize()
        self.assertTrue(decision.authorized, decision.detail)
        self.assertEqual(decision.facts["release_initiator"], "repository_owner")

        event = self.event(self.git.reviewed, run_attempt=2)
        transport = self.valid_transport()
        transport.responses[trust.workflow_run_api(REPOSITORY, RUN_ID)] = (
            self.run_payload(self.git.reviewed, run_attempt=2)
        )
        decision = self.authorize(transport=transport, event=event)
        self.assertTrue(decision.authorized, decision.detail)

    def test_forged_event_actor_and_login_hints_are_not_trusted(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        event = self.event(self.git.reviewed)
        for container in (event, event["workflow_run"]):
            container["actor"] = {
                "id": OWNER_ID,
                "login": OWNER,
                "type": "User",
            }
            container["triggering_actor"] = {
                "id": OWNER_ID,
                "login": OWNER,
                "type": "User",
            }

        transport = self.valid_transport()
        transport.responses[trust.workflow_run_api(REPOSITORY, RUN_ID)] = (
            self.run_payload(
                self.git.reviewed,
                actor_id=OWNER_ID + 1,
                triggering_actor_id=OWNER_ID + 1,
                actor_login=OWNER,
            )
        )
        self.assert_refused(
            self.authorize(transport=transport, event=event),
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
        )

        forged = self.event(self.git.reviewed)
        for container in (forged, forged["workflow_run"]):
            container["actor"] = {
                "id": OWNER_ID + 1,
                "login": "outsider",
                "type": "User",
            }
            container["triggering_actor"] = {
                "id": OWNER_ID + 1,
                "login": "outsider",
                "type": "User",
            }
        decision = self.authorize(transport=self.valid_transport(), event=forged)
        self.assertTrue(decision.authorized, decision.detail)

    def test_canonical_initiator_ids_must_match_the_personal_owner(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        cases: list[tuple[str, int, dict[str, object]]] = [
            (
                "collaborator",
                1,
                {
                    "actor_id": OWNER_ID + 1,
                    "triggering_actor_id": OWNER_ID + 1,
                    "actor_login": "collaborator",
                },
            ),
            (
                "bot",
                1,
                {
                    "actor_id": OWNER_ID + 1,
                    "triggering_actor_id": OWNER_ID + 1,
                    "actor_login": f"{OWNER}[bot]",
                    "actor_type": "Bot",
                },
            ),
            (
                "same login wrong id",
                1,
                {
                    "actor_id": OWNER_ID + 1,
                    "triggering_actor_id": OWNER_ID + 1,
                    "actor_login": OWNER,
                },
            ),
            (
                "actor owner but triggering outsider",
                1,
                {"triggering_actor_id": OWNER_ID + 1},
            ),
            (
                "actor outsider but triggering owner",
                1,
                {"actor_id": OWNER_ID + 1},
            ),
            (
                "outsider rerun",
                2,
                {
                    "actor_id": OWNER_ID + 1,
                    "triggering_actor_id": OWNER_ID + 1,
                },
            ),
            (
                "mixed owner and outsider rerun",
                2,
                {"triggering_actor_id": OWNER_ID + 1},
            ),
        ]
        for label, run_attempt, options in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[trust.workflow_run_api(REPOSITORY, RUN_ID)] = (
                    self.run_payload(
                        self.git.reviewed,
                        run_attempt=run_attempt,
                        **options,
                    )
                )
                event = self.event(self.git.reviewed, run_attempt=run_attempt)
                self.assert_refused(
                    self.authorize(transport=transport, event=event),
                    trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
                )

    def test_missing_or_malformed_initiator_metadata_fails_closed(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)

        def remove_actor(run: dict[str, object]) -> None:
            del run["actor"]

        def remove_triggering_actor(run: dict[str, object]) -> None:
            del run["triggering_actor"]

        def actor(value: object) -> object:
            return lambda run: run.__setitem__("actor", value)

        def triggering_actor(value: object) -> object:
            return lambda run: run.__setitem__("triggering_actor", value)

        bad_ids: tuple[object, ...] = (None, True, False, 0, -1, "200", 200.0)
        cases: list[tuple[str, object]] = [
            ("missing actor", remove_actor),
            ("null actor", actor(None)),
            ("actor not an object", actor("actor")),
            ("actor id missing", actor({"login": OWNER, "type": "User"})),
            ("missing triggering actor", remove_triggering_actor),
            ("null triggering actor", triggering_actor(None)),
            (
                "triggering actor not an object",
                triggering_actor(["not", "an", "actor"]),
            ),
            (
                "triggering actor id missing",
                triggering_actor({"login": OWNER, "type": "User"}),
            ),
        ]
        for value in bad_ids:
            cases.append(
                (
                    f"actor id {value!r}",
                    actor({"id": value, "login": OWNER, "type": "User"}),
                )
            )
            cases.append(
                (
                    f"triggering actor id {value!r}",
                    triggering_actor(
                        {"id": value, "login": OWNER, "type": "User"}
                    ),
                )
            )
        for label, mutate in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                run = transport.responses[trust.workflow_run_api(REPOSITORY, RUN_ID)]
                mutate(run)  # type: ignore[operator]
                self.assert_refused(
                    self.authorize(transport=transport),
                    trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
                )

    def test_owner_metadata_requires_a_positive_personal_user_id(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)

        def owner_without_id(payload: dict[str, object]) -> None:
            del payload["owner"]["id"]  # type: ignore[index]

        def owner_without_type(payload: dict[str, object]) -> None:
            del payload["owner"]["type"]  # type: ignore[index]

        def owner_id(value: object) -> object:
            return lambda payload: payload["owner"].__setitem__("id", value)

        def owner_type(value: object) -> object:
            return lambda payload: payload["owner"].__setitem__("type", value)

        cases: list[tuple[str, object]] = [
            ("owner missing", lambda payload: payload.pop("owner")),
            ("owner null", lambda payload: payload.__setitem__("owner", None)),
            ("owner id missing", owner_without_id),
            ("owner id null", owner_id(None)),
            ("owner id true", owner_id(True)),
            ("owner id false", owner_id(False)),
            ("owner id zero", owner_id(0)),
            ("owner id negative", owner_id(-1)),
            ("owner id string", owner_id(str(OWNER_ID))),
            ("owner id float", owner_id(float(OWNER_ID))),
            ("owner type missing", owner_without_type),
            ("organization owner", owner_type("Organization")),
            ("bot owner", owner_type("Bot")),
            ("owner type null", owner_type(None)),
        ]
        for label, mutate in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                payload = transport.responses[trust.repository_api(REPOSITORY)]
                mutate(payload)  # type: ignore[operator]
                self.assert_refused(
                    self.authorize(transport=transport),
                    trust.Refusal.REPOSITORY_OWNER_UNTRUSTED,
                )

    def test_unsupported_organization_refuses_before_org_secret_scope(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        transport = self.valid_transport(owner_type="Organization")
        decision = self.authorize(transport=transport)
        self.assert_refused(decision, trust.Refusal.REPOSITORY_OWNER_UNTRUSTED)
        self.assertNotIn(
            ("get_list", trust.organization_secrets_api(OWNER)),
            transport.calls,
        )

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
                "null bypass metadata",
                {
                    **base,
                    "required_pull_request_reviews": {
                        **valid_reviews,
                        "bypass_pull_request_allowances": None,
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

    def test_classic_bypass_absent_composed_ruleset_proof(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        classic = self.classic_protection_without_bypass()
        detail = self.valid_branch_ruleset()
        # Summaries contribute only positive ids. Target/enforcement here are
        # deliberately misleading and must not affect the decision.
        summary = {"id": 11, "target": "tag", "enforcement": "disabled"}

        stdout = self.gh_fixture_stdout()
        stdout[trust.branch_protection_api(REPOSITORY)] = json.dumps(classic)
        stdout[trust.branch_rulesets_api(REPOSITORY)] = json.dumps([[summary]])
        stdout[trust.ruleset_api(REPOSITORY, 11)] = json.dumps(detail)
        decision, commands = self.authorize_via_gh(stdout)
        self.assertTrue(decision.authorized, decision.detail)
        self.assertEqual(decision.reason, trust.Refusal.AUTHORIZED)
        branch_path = trust.branch_rulesets_api(REPOSITORY)
        self.assertIn("targets=branch", branch_path)
        branch_commands = [
            command for command in commands if command[-1] == branch_path
        ]
        self.assertEqual(len(branch_commands), 1)
        self.assertIn("--paginate", branch_commands[0])
        self.assertIn("--slurp", branch_commands[0])

        # Explicit present-empty classic bypass still needs no ruleset proof.
        decision, _ = self.authorize_via_gh(self.gh_fixture_stdout())
        self.assertTrue(decision.authorized, decision.detail)

        # The same absent classic field without a branch ruleset is refused.
        no_proof = self.gh_fixture_stdout()
        no_proof[trust.branch_protection_api(REPOSITORY)] = json.dumps(classic)
        decision, _ = self.authorize_via_gh(no_proof)
        self.assert_refused(decision, trust.Refusal.BRANCH_RULES_ABSENT)

    def test_branch_ruleset_proof_rejects_extra_conditions_key(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        detail = self.valid_branch_ruleset()
        conditions = detail["conditions"]
        assert isinstance(conditions, dict)
        conditions["unknown_scope"] = "narrow"
        stdout = self.gh_fixture_stdout()
        stdout[trust.branch_protection_api(REPOSITORY)] = json.dumps(
            self.classic_protection_without_bypass()
        )
        stdout[trust.branch_rulesets_api(REPOSITORY)] = json.dumps([[{"id": 11}]])
        stdout[trust.ruleset_api(REPOSITORY, 11)] = json.dumps(detail)
        decision, _ = self.authorize_via_gh(stdout)
        self.assert_refused(decision, trust.Refusal.BRANCH_RULES_INSUFFICIENT)

    def test_branch_ruleset_proof_rejects_extra_ref_name_key(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        detail = self.valid_branch_ruleset()
        conditions = detail["conditions"]
        assert isinstance(conditions, dict)
        ref_name = conditions["ref_name"]
        assert isinstance(ref_name, dict)
        ref_name["unknown_scope"] = "narrow"
        stdout = self.gh_fixture_stdout()
        stdout[trust.branch_protection_api(REPOSITORY)] = json.dumps(
            self.classic_protection_without_bypass()
        )
        stdout[trust.branch_rulesets_api(REPOSITORY)] = json.dumps([[{"id": 11}]])
        stdout[trust.ruleset_api(REPOSITORY, 11)] = json.dumps(detail)
        decision, _ = self.authorize_via_gh(stdout)
        self.assert_refused(decision, trust.Refusal.BRANCH_RULES_INSUFFICIENT)

    def test_present_classic_bypass_is_not_rescued_by_ruleset_proof(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        cases: list[tuple[str, object]] = [
            ("null", None),
            ("unknown allowances", {}),
            (
                "users bypass",
                {"users": [{"login": "untrusted"}], "teams": [], "apps": []},
            ),
            (
                "malformed users",
                {"users": "nobody", "teams": [], "apps": []},
            ),
        ]
        for label, bypass in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                protection = self.valid_protection()
                reviews = dict(protection["required_pull_request_reviews"])  # type: ignore[arg-type]
                reviews["bypass_pull_request_allowances"] = bypass
                protection["required_pull_request_reviews"] = reviews
                transport.responses[trust.branch_protection_api(REPOSITORY)] = (
                    protection
                )
                self.install_branch_rulesets(
                    transport, [self.valid_branch_ruleset()]
                )
                self.assert_refused(
                    self.authorize(transport=transport),
                    trust.Refusal.BRANCH_PROTECTION_INSUFFICIENT,
                )
                branch_path = trust.branch_rulesets_api(REPOSITORY)
                self.assertFalse(
                    any(path == branch_path for _, path in transport.calls)
                )

    def test_branch_ruleset_proof_rejects_unsafe_or_incomplete_details(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        classic = self.classic_protection_without_bypass()
        cases: list[
            tuple[
                str,
                dict[str, object],
                list[dict[str, object]],
                list[dict[str, object]] | None,
                list[int] | None,
                trust.Refusal,
            ]
        ] = []

        def base_detail(**kwargs: object) -> dict[str, object]:
            return copy.deepcopy(self.valid_branch_ruleset(**kwargs))  # type: ignore[arg-type]

        def add(
            label: str,
            detail: dict[str, object],
            expected: trust.Refusal = trust.Refusal.BRANCH_RULES_INSUFFICIENT,
            *,
            summaries: list[dict[str, object]] | None = None,
            detail_ids: list[int] | None = None,
            protection: dict[str, object] | None = None,
        ) -> None:
            cases.append(
                (
                    label,
                    protection or classic,
                    [detail],
                    summaries,
                    detail_ids,
                    expected,
                )
            )

        detail = base_detail()
        detail.pop("bypass_actors")
        add("missing bypass actors", detail)

        detail = base_detail()
        detail["bypass_actors"] = None
        add("hidden bypass actors", detail)

        detail = base_detail()
        detail["bypass_actors"] = [{"actor_type": "OrganizationAdmin"}]
        add("nonempty bypass actors", detail)

        detail = base_detail()
        detail["source_type"] = "Organization"
        detail["source"] = OWNER
        add("parent source", detail)

        detail = base_detail()
        detail["source"] = "other/repo"
        add("different repository source", detail)

        detail = base_detail(ruleset_id=12)
        add(
            "detail id mismatch",
            detail,
            trust.Refusal.BRANCH_RULES_UNKNOWN,
            summaries=[{"id": 11}],
            detail_ids=[11],
        )

        detail = base_detail()
        detail["conditions"] = {
            "ref_name": {"include": ["refs/heads/release"], "exclude": []}
        }
        add("wrong branch include", detail)

        detail = base_detail()
        detail["conditions"] = {
            "ref_name": {
                "include": [f"refs/heads/{trust.DEFAULT_BRANCH}"],
                "exclude": ["refs/heads/main"],
            }
        }
        add("branch exclusion", detail)

        detail = base_detail()
        detail["target"] = "tag"
        add("tag target detail", detail)

        detail = base_detail()
        detail["enforcement"] = "disabled"
        add("disabled ruleset", detail)

        detail = base_detail()
        detail["enforcement"] = "evaluate"
        add("evaluate ruleset", detail)

        classic_two = copy.deepcopy(classic)
        reviews_two = dict(classic_two["required_pull_request_reviews"])  # type: ignore[arg-type]
        reviews_two["required_approving_review_count"] = 2
        classic_two["required_pull_request_reviews"] = reviews_two

        detail = base_detail()
        detail["rules"][0]["parameters"][  # type: ignore[index]
            "required_approving_review_count"
        ] = 1
        add("proof count below classic", detail, protection=classic_two)

        detail = base_detail()
        detail["rules"][0]["parameters"][  # type: ignore[index]
            "required_approving_review_count"
        ] = True
        add("boolean proof count", detail)

        detail = base_detail()
        detail["rules"][0]["parameters"][  # type: ignore[index]
            "required_approving_review_count"
        ] = 0
        add("zero proof count", detail)

        detail = base_detail()
        detail["rules"] = []
        add("missing pull request rule", detail)

        detail = base_detail()
        detail["rules"][0].pop("parameters")
        add("missing rule parameters", detail)

        detail = base_detail()
        detail["rules"][0]["parameters"][  # type: ignore[index]
            "dismiss_stale_reviews_on_push"
        ] = False
        add("dismiss stale disabled", detail)

        detail = base_detail()
        detail["rules"][0]["parameters"][  # type: ignore[index]
            "require_last_push_approval"
        ] = False
        add("last push approval disabled", detail)

        detail = base_detail()
        detail["rules"][0]["parameters"].pop(  # type: ignore[index]
            "require_last_push_approval"
        )
        add("missing last push approval", detail)

        detail = base_detail()
        detail["rules"].append(copy.deepcopy(detail["rules"][0]))
        add("multiple pull request rules", detail)

        first = base_detail(ruleset_id=11)
        first["bypass_actors"] = [{"actor_type": "OrganizationAdmin"}]
        second = base_detail(ruleset_id=12)
        second["rules"] = []
        cases.append(
            (
                "split proof across rulesets",
                classic,
                [first, second],
                None,
                None,
                trust.Refusal.BRANCH_RULES_INSUFFICIENT,
            )
        )

        detail = base_detail()
        cases.append(
            (
                "duplicate summary ids",
                classic,
                [detail],
                [{"id": 11}, {"id": 11}],
                [11],
                trust.Refusal.BRANCH_RULES_UNKNOWN,
            )
        )

        for (
            label,
            protection,
            details,
            summaries,
            detail_ids,
            expected,
        ) in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[trust.branch_protection_api(REPOSITORY)] = (
                    copy.deepcopy(protection)
                )
                self.install_branch_rulesets(
                    transport,
                    details,
                    summaries=summaries,
                    detail_ids=detail_ids,
                )
                self.assert_refused(
                    self.authorize(transport=transport), expected
                )

    def test_branch_ruleset_proof_transport_errors_are_fixed_enums(self) -> None:
        self.git.lightweight_tag(TAG, self.git.reviewed)
        classic = self.classic_protection_without_bypass()
        cases: list[tuple[str, str, object, trust.Refusal]] = [
            (
                "list absent",
                "list",
                trust.ApiResponse(404, None),
                trust.Refusal.BRANCH_RULES_ABSENT,
            ),
            (
                "list empty",
                "list",
                [],
                trust.Refusal.BRANCH_RULES_ABSENT,
            ),
            (
                "list forbidden",
                "list",
                trust.ApiResponse(403, None),
                trust.Refusal.BRANCH_RULES_UNREADABLE,
            ),
            (
                "list unknown",
                "list",
                trust.ApiResponse(500, None),
                trust.Refusal.BRANCH_RULES_UNKNOWN,
            ),
            (
                "detail absent",
                "detail",
                trust.ApiResponse(404, None),
                trust.Refusal.BRANCH_RULES_UNKNOWN,
            ),
            (
                "detail forbidden",
                "detail",
                trust.ApiResponse(403, None),
                trust.Refusal.BRANCH_RULES_UNREADABLE,
            ),
            (
                "detail unknown",
                "detail",
                trust.ApiResponse(500, None),
                trust.Refusal.BRANCH_RULES_UNKNOWN,
            ),
        ]
        for label, endpoint, response, expected in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[trust.branch_protection_api(REPOSITORY)] = (
                    copy.deepcopy(classic)
                )
                if endpoint == "list":
                    transport.responses[trust.branch_rulesets_api(REPOSITORY)] = (
                        response
                    )
                else:
                    transport.responses[trust.branch_rulesets_api(REPOSITORY)] = [
                        {"id": 11}
                    ]
                    transport.responses[trust.ruleset_api(REPOSITORY, 11)] = (
                        response
                    )
                self.assert_refused(
                    self.authorize(transport=transport), expected
                )

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

    def test_tag_coverage_requires_exact_refs_tags_vstar(self) -> None:
        def detail(includes: object, excludes: object = []) -> dict[str, object]:
            return {
                "conditions": {
                    "ref_name": {"include": includes, "exclude": excludes}
                }
            }

        self.assertIs(trust._covers_all_v_tags(detail(["refs/tags/v*"])), True)
        for label, include, excludes in (
            ("bare v*", ["v*"], []),
            ("all tags", ["refs/tags/*"], []),
            ("all refs", ["refs/*"], []),
            ("everything", ["*"], []),
            ("exact plus bare", ["refs/tags/v*", "v*"], []),
            ("exact plus broader", ["refs/tags/v*", "refs/tags/*"], []),
            ("duplicate exact", ["refs/tags/v*", "refs/tags/v*"], []),
            ("empty", [], []),
            ("excluded release tag", ["refs/tags/v*"], ["refs/tags/v1.2.3"]),
            ("excluded broad ref", ["refs/tags/v*"], ["refs/tags/*"]),
        ):
            with self.subTest(case=label):
                self.assertIs(
                    trust._covers_all_v_tags(detail(include, excludes)), False
                )
        for label, includes, excludes in (
            ("malformed include", "refs/tags/v*", []),
            ("malformed include item", ["refs/tags/v*", 7], []),
            ("malformed exclude", ["refs/tags/v*"], "refs/tags/v1.2.3"),
        ):
            with self.subTest(case=label):
                self.assertIs(trust._covers_all_v_tags(detail(includes, excludes)), None)
        for label, payload in (
            ("missing conditions", {}),
            ("conditions not an object", {"conditions": []}),
            ("missing ref_name", {"conditions": {}}),
            ("ref_name not an object", {"conditions": {"ref_name": "v*"}}),
        ):
            with self.subTest(case=label):
                self.assertIs(trust._covers_all_v_tags(payload), None)

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
        cases: list[tuple[str, str, object, trust.Refusal]] = [
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
                trust.Refusal.SECRETS_REPOSITORY_LEAK,
            ),
            (
                "repository scoped optional windows certificate",
                trust.repository_secrets_api(REPOSITORY),
                {"secrets": [{"name": "WINDOWS_CERTIFICATE"}]},
                trust.Refusal.SECRETS_REPOSITORY_LEAK,
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
                trust.Refusal.SECRETS_ENVIRONMENT_UNKNOWN,
            ),
        ]
        for label, path, payload, expected in cases:
            with self.subTest(case=label):
                transport = self.valid_transport()
                transport.responses[path] = payload
                self.assert_refused(self.authorize(transport=transport), expected)

    def test_organization_secret_scope_is_isolated_from_owner_gate(self) -> None:
        # A composed flow must refuse an organization-owned repository before
        # any organization secret metadata is treated as a policy answer.
        self.git.lightweight_tag(TAG, self.git.reviewed)
        self.assert_refused(
            self.authorize(transport=self.valid_transport(owner_type="Organization")),
            trust.Refusal.REPOSITORY_OWNER_UNTRUSTED,
        )

        # The scope check is exercised directly, with an explicit organization
        # RepositoryInfo, so these tests cannot accidentally bypass the
        # personal-owner gate in the composed validator.
        repository_info = trust.RepositoryInfo(
            repository_id=REPOSITORY_ID,
            full_name=REPOSITORY,
            default_branch="main",
            owner_login=OWNER,
            owner_type="Organization",
            owner_id=OWNER_ID,
        )
        cases: list[tuple[str, object, trust.Refusal]] = [
            (
                "organization scoped signing credential",
                {"secrets": [{"name": "MACOS_CERTIFICATE"}]},
                trust.Refusal.SECRETS_ORGANIZATION_LEAK,
            ),
            (
                "organization scoped optional certificate",
                {"secrets": [{"name": "WINDOWS_CERTIFICATE"}]},
                trust.Refusal.SECRETS_ORGANIZATION_LEAK,
            ),
            (
                "organization secret listing absent",
                trust.ApiResponse(404, None),
                trust.Refusal.SECRETS_ORGANIZATION_ABSENT,
            ),
        ]
        for label, payload, expected in cases:
            with self.subTest(case=label):
                transport = self.valid_transport(owner_type="Organization")
                transport.responses[trust.organization_secrets_api(OWNER)] = payload
                with self.assertRaises(trust.ReleaseRefusal) as caught:
                    trust._check_secrets(transport, REPOSITORY, repository_info)
                self.assertEqual(caught.exception.reason, expected)

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
            trust.branch_rulesets_api(REPOSITORY),
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
        stdout = self.gh_fixture_stdout()
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
        }
        called = {command[-1] for command in commands}
        self.assertTrue(paginated <= called)
        self.assertNotIn(trust.organization_secrets_api(OWNER), called)
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
