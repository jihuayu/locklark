#!/usr/bin/env python3
"""Source-only routing for a default-branch repository_dispatch release.

This module is wired by ``.github/workflows/desktop-release.yml`` in the C2b
checkpoint. It binds a ``repository_dispatch`` event with action
``desktop-release`` to the canonical current run, then reuses the C1
release-trust policy gates before resolving the exact candidate tag and its
default-branch ancestry. Wiring does not make the source contract an actual
external policy acceptance.

The event supplies only the release tag through ``client_payload``. Run id,
attempt, server SHA, workflow SHA, repository, and git path are supplied by the
trusted caller/environment, never by event payload overrides. API access is
read-only and restricted to the existing metadata allowlist.

A successful decision proves only that the supplied source metadata satisfies
this source contract. It is not evidence that any external repository policy,
credential scope, or required ruleset has actually been configured or accepted.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

import authorize_desktop_release as trust


DESKTOP_RELEASE_WORKFLOW_PATH = ".github/workflows/desktop-release.yml"
DISPATCH_ACTION = "desktop-release"
_ALLOWED_WORKFLOW_PATHS = frozenset(
    {
        DESKTOP_RELEASE_WORKFLOW_PATH,
        DESKTOP_RELEASE_WORKFLOW_PATH + "@main",
        DESKTOP_RELEASE_WORKFLOW_PATH + "@refs/heads/main",
    }
)
_SAFE_REFUSAL_DETAIL = "repository_dispatch authorization refused"
_SUCCESS_DETAIL = (
    "repository_dispatch, exact candidate, protected main ancestry, tag "
    "immutability, environment branch restriction, and credential scope "
    "metadata all satisfied"
)


@dataclass(frozen=True)
class TrustedRunBinding:
    run_id: int
    run_attempt: int
    sha: str
    workflow_sha: str


def _refuse(reason: trust.Refusal, detail: str) -> None:
    raise trust.ReleaseRefusal(reason, detail)


def _positive_env_int(value: object, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        _refuse(
            trust.Refusal.ARGUMENT_INVALID,
            f"trusted {label} is missing or invalid",
        )
    return int(value)


def _strict_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not trust._SHA_RE.fullmatch(value):
        _refuse(
            trust.Refusal.ARGUMENT_INVALID,
            f"trusted {label} is not a full 40-hex SHA",
        )
    return value


def trusted_run_binding(
    run_id: object,
    run_attempt: object,
    sha: object,
    workflow_sha: object,
) -> TrustedRunBinding:
    """Validate caller-provided current-run facts without consulting payload."""

    return TrustedRunBinding(
        run_id=_positive_env_int(run_id, "run id"),
        run_attempt=_positive_env_int(run_attempt, "run attempt"),
        sha=_strict_sha(sha, "server SHA"),
        workflow_sha=_strict_sha(workflow_sha, "workflow SHA"),
    )


def trusted_workflow_path(value: object) -> str:
    """Accept only the exact workflow path or its default-branch suffixes."""

    if not isinstance(value, str) or value not in _ALLOWED_WORKFLOW_PATHS:
        _refuse(
            trust.Refusal.WORKFLOW_RUN_PATH_UNTRUSTED,
            "workflow path is not the exact desktop release path",
        )
    return DESKTOP_RELEASE_WORKFLOW_PATH


def load_dispatch_event(event_path: str | Path) -> object:
    """Load a bounded local event file without fetching or mutating anything."""

    path = Path(event_path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        _refuse(trust.Refusal.EVENT_ABSENT, "repository_dispatch event is absent")
    except OSError:
        _refuse(
            trust.Refusal.EVENT_UNREADABLE,
            "repository_dispatch event is unreadable",
        )
    if len(raw) > 4 * 1024 * 1024:
        _refuse(
            trust.Refusal.EVENT_UNREADABLE,
            "repository_dispatch event is too large",
        )
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        _refuse(
            trust.Refusal.EVENT_UNREADABLE,
            "repository_dispatch event is not valid JSON",
        )


def _parse_dispatch_event(event: object) -> tuple[str, int, str, int]:
    event = trust._mapping(
        event,
        trust.Refusal.EVENT_INVALID,
        "repository_dispatch event is not an object",
    )
    if event.get("action") != DISPATCH_ACTION:
        _refuse(
            trust.Refusal.EVENT_INVALID,
            "repository_dispatch action is not desktop-release",
        )
    payload = trust._mapping(
        event.get("client_payload"),
        trust.Refusal.EVENT_INVALID,
        "repository_dispatch client_payload is absent or malformed",
    )
    if set(payload) != {"tag"}:
        _refuse(
            trust.Refusal.EVENT_INVALID,
            "repository_dispatch client_payload must contain exactly tag",
        )
    tag = payload.get("tag")
    if not isinstance(tag, str) or not trust._TAG_RE.fullmatch(tag):
        _refuse(
            trust.Refusal.TAG_INVALID,
            "repository_dispatch tag is not a strict semantic version",
        )
    repository = trust._mapping(
        event.get("repository"),
        trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
        "repository_dispatch repository metadata is absent or malformed",
    )
    repository_id = trust._positive_int(
        repository.get("id"),
        trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
        "repository_dispatch repository id is invalid",
    )
    repository_full_name = trust._text(
        repository.get("full_name"),
        trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
        "repository_dispatch repository full_name is invalid",
    )
    sender = trust._mapping(
        event.get("sender"),
        trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
        "repository_dispatch sender metadata is absent or malformed",
    )
    sender_id = trust._positive_int(
        sender.get("id"),
        trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
        "repository_dispatch sender id is invalid",
    )
    if sender.get("type") != "User":
        _refuse(
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            "repository_dispatch sender is not a personal user",
        )
    branch = event.get("branch")
    if not isinstance(branch, str) or branch != trust.DEFAULT_BRANCH:
        _refuse(
            trust.Refusal.DEFAULT_BRANCH_UNTRUSTED,
            "repository_dispatch did not explicitly target the default branch",
        )
    return tag, repository_id, repository_full_name, sender_id


def _bind_current_run(
    run_payload: object,
    repository: trust.RepositoryInfo,
    event_repository_id: int,
    event_repository_full_name: str,
    sender_id: int,
    binding: TrustedRunBinding,
) -> Mapping[str, object]:
    if (
        event_repository_id != repository.repository_id
        or event_repository_full_name.casefold()
        != repository.full_name.casefold()
    ):
        _refuse(
            trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            "repository_dispatch repository does not match canonical repository",
        )

    run = trust._mapping(
        run_payload,
        trust.Refusal.WORKFLOW_RUN_UNKNOWN,
        "canonical current run metadata is not an object",
    )
    run_id = trust._positive_int(
        run.get("id"),
        trust.Refusal.WORKFLOW_RUN_MISMATCH,
        "canonical run id is invalid",
    )
    if run_id != binding.run_id:
        _refuse(
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            "canonical run id differs from trusted run id",
        )
    run_attempt = trust._positive_int(
        run.get("run_attempt"),
        trust.Refusal.WORKFLOW_RUN_MISMATCH,
        "canonical run attempt is invalid",
    )
    if run_attempt != binding.run_attempt:
        _refuse(
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            "canonical run attempt differs from trusted attempt",
        )
    if (
        trust._text(
            run.get("event"),
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            "canonical run event is invalid",
        )
        != "repository_dispatch"
    ):
        _refuse(
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            "canonical run is not a repository_dispatch run",
        )
    if (
        trust._text(
            run.get("status"),
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            "canonical run status is invalid",
        )
        != "in_progress"
    ):
        _refuse(
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            "canonical run is not in progress",
        )
    if "conclusion" not in run or run.get("conclusion") is not None:
        _refuse(
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            "canonical run conclusion is not null",
        )
    if (
        trust._text(
            run.get("head_branch"),
            trust.Refusal.DEFAULT_BRANCH_UNTRUSTED,
            "canonical run head_branch is invalid",
        )
        != trust.DEFAULT_BRANCH
    ):
        _refuse(
            trust.Refusal.DEFAULT_BRANCH_UNTRUSTED,
            "canonical run did not run from the default branch",
        )
    trusted_workflow_path(run.get("path"))
    head_sha = trust._sha(
        run.get("head_sha"),
        trust.Refusal.WORKFLOW_RUN_HEAD_SHA_INVALID,
        "canonical run head_sha is invalid",
    )
    if head_sha != binding.sha or head_sha != binding.workflow_sha:
        _refuse(
            trust.Refusal.WORKFLOW_RUN_MISMATCH,
            "canonical run head SHA does not equal trusted server and workflow SHAs",
        )

    run_repository = trust._mapping(
        run.get("repository"),
        trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
        "canonical run repository metadata is invalid",
    )
    head_repository = trust._mapping(
        run.get("head_repository"),
        trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
        "canonical run head_repository metadata is invalid",
    )
    for name, value in (
        ("run repository", run_repository),
        ("head repository", head_repository),
    ):
        repository_id = trust._positive_int(
            value.get("id"),
            trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            f"canonical {name} id is invalid",
        )
        repository_name = trust._text(
            value.get("full_name"),
            trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            f"canonical {name} full_name is invalid",
        )
        if (
            repository_id != repository.repository_id
            or repository_name.casefold() != repository.full_name.casefold()
        ):
            _refuse(
                trust.Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
                f"canonical {name} differs from the canonical repository",
            )

    actor = trust._mapping(
        run.get("actor"),
        trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
        "canonical run actor metadata is invalid",
    )
    actor_id = trust._positive_int(
        actor.get("id"),
        trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
        "canonical run actor id is invalid",
    )
    if actor.get("type") != "User":
        _refuse(
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            "canonical run actor is not a personal user",
        )
    triggering_actor = trust._mapping(
        run.get("triggering_actor"),
        trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
        "canonical run triggering_actor metadata is invalid",
    )
    triggering_actor_id = trust._positive_int(
        triggering_actor.get("id"),
        trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
        "canonical run triggering_actor id is invalid",
    )
    if triggering_actor.get("type") != "User":
        _refuse(
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            "canonical run triggering actor is not a personal user",
        )
    if (
        actor_id != repository.owner_id
        or triggering_actor_id != repository.owner_id
        or sender_id != repository.owner_id
    ):
        _refuse(
            trust.Refusal.RELEASE_INITIATOR_UNTRUSTED,
            "canonical actors and sender must all be the repository owner",
        )
    return run


def _run_dispatch_authorization(
    *,
    event: object,
    repository: str,
    git_repo: Path,
    binding: TrustedRunBinding,
    transport: trust.ReadOnlyTransport,
) -> Mapping[str, object]:
    if not isinstance(repository, str) or not trust._REPOSITORY_RE.fullmatch(
        repository
    ):
        _refuse(trust.Refusal.REPOSITORY_INVALID, "repository must be owner/name")

    tag, event_repository_id, event_repository_name, sender_id = (
        _parse_dispatch_event(event)
    )
    git = trust.GitReader(git_repo)
    git.verify_repository()
    tag_info = git.resolve_tag(tag)
    repository_info = trust._load_repository_info(transport, repository)

    run_payload = trust._api_call(
        transport,
        trust.workflow_run_api(repository, binding.run_id),
        list_response=False,
        absent=trust.Refusal.WORKFLOW_RUN_ABSENT,
        unreadable=trust.Refusal.WORKFLOW_RUN_UNREADABLE,
        unknown=trust.Refusal.WORKFLOW_RUN_UNKNOWN,
    )
    _bind_current_run(
        run_payload,
        repository_info,
        event_repository_id,
        event_repository_name,
        sender_id,
        binding,
    )

    default_branch_sha = trust._check_policy_metadata(
        transport, repository, repository_info, git
    )
    git.ensure_commit(
        binding.workflow_sha,
        trust.Refusal.WORKFLOW_OBJECT_MISSING,
    )
    if not git.is_ancestor(tag_info.commit, binding.workflow_sha):
        _refuse(
            trust.Refusal.CANDIDATE_NOT_ANCESTOR,
            "candidate tag commit is not an ancestor of the workflow SHA",
        )
    if not git.is_ancestor(binding.workflow_sha, default_branch_sha):
        _refuse(
            trust.Refusal.CANDIDATE_NOT_ANCESTOR,
            "workflow SHA is not an ancestor of protected main",
        )

    version = tag[1:]
    return {
        "repository": repository_info.full_name,
        "repository_id": repository_info.repository_id,
        "tag": tag,
        "tag_object": tag_info.tag_object,
        "tag_commit": tag_info.commit,
        "tag_annotated": tag_info.annotated,
        "version": version,
        "prerelease": "-" in version.split("+", 1)[0],
        "event": "repository_dispatch",
        "workflow_run_id": binding.run_id,
        "workflow_run_attempt": binding.run_attempt,
        "workflow_sha": binding.workflow_sha,
        "default_branch": trust.DEFAULT_BRANCH,
        "default_branch_commit": default_branch_sha,
        "environment": trust.PRODUCTION_ENVIRONMENT,
        "required_tag_rules": sorted(trust.REQUIRED_TAG_RULES),
        "production_secret_scope": "environment",
    }


def authorize_desktop_release_dispatch(
    *,
    event: object | None = None,
    event_path: str | Path | None = None,
    repository: str,
    git_repo: str | Path,
    run_id: object,
    run_attempt: object,
    sha: object,
    workflow_sha: object,
    transport: trust.ReadOnlyTransport | None = None,
) -> trust.Decision:
    """Authorize a default-branch repository_dispatch release request."""

    if event is not None and event_path is not None:
        return trust.Decision(
            "REFUSE",
            trust.Refusal.ARGUMENT_INVALID,
            _SAFE_REFUSAL_DETAIL,
        )
    if not isinstance(git_repo, (str, os.PathLike)):
        return trust.Decision(
            "REFUSE",
            trust.Refusal.ARGUMENT_INVALID,
            _SAFE_REFUSAL_DETAIL,
        )
    if event_path is not None and not isinstance(event_path, (str, os.PathLike)):
        return trust.Decision(
            "REFUSE",
            trust.Refusal.ARGUMENT_INVALID,
            _SAFE_REFUSAL_DETAIL,
        )
    if transport is None:
        transport = trust.GhApiTransport()
    try:
        if event is None:
            if event_path is None:
                _refuse(
                    trust.Refusal.EVENT_ABSENT,
                    "repository_dispatch event is absent",
                )
            event = load_dispatch_event(event_path)
        binding = trusted_run_binding(run_id, run_attempt, sha, workflow_sha)
        facts = _run_dispatch_authorization(
            event=event,
            repository=repository,
            git_repo=Path(git_repo),
            binding=binding,
            transport=transport,
        )
    except trust.ReleaseRefusal as exc:
        # Only the fixed enum is exposed. Event values, actor values, secret
        # names, and raw transport details are intentionally discarded.
        return trust.Decision("REFUSE", exc.reason, _SAFE_REFUSAL_DETAIL)
    except Exception:
        return trust.Decision(
            "REFUSE",
            trust.Refusal.INTERNAL_ERROR,
            _SAFE_REFUSAL_DETAIL,
        )
    return trust.Decision(
        "AUTHORIZE",
        trust.Refusal.AUTHORIZED,
        _SUCCESS_DETAIL,
        facts,
    )


def _output_values(facts: Mapping[str, object]) -> dict[str, str]:
    tag = facts.get("tag")
    commit = facts.get("tag_commit")
    version = facts.get("version")
    prerelease = facts.get("prerelease")
    if (
        not isinstance(tag, str)
        or not isinstance(commit, str)
        or not isinstance(version, str)
        or not isinstance(prerelease, bool)
    ):
        _refuse(
            trust.Refusal.ARGUMENT_INVALID,
            "authorized outputs are incomplete or malformed",
        )
    values = {
        "tag": tag,
        "commit": commit,
        "version": version,
        "prerelease": "true" if prerelease else "false",
    }
    for value in values.values():
        if not value or "\n" in value or "\r" in value:
            _refuse(
                trust.Refusal.ARGUMENT_INVALID,
                "authorized outputs contain unsafe characters",
            )
    return values


def write_github_output(path: str | Path, facts: Mapping[str, object]) -> None:
    """Append validated release outputs only after an authorization decision."""

    values = _output_values(facts)
    payload = "".join(f"{key}={value}\n" for key, value in values.items())
    try:
        with Path(path).open("a", encoding="utf-8") as output:
            output.write(payload)
    except OSError:
        _refuse(
            trust.Refusal.ARGUMENT_INVALID,
            "GITHUB_OUTPUT is not writable",
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Source-only default-branch repository_dispatch release routing. "
            "This does not dispatch, write metadata, fetch credentials, or "
            "change repository policy."
        )
    )
    parser.add_argument("--event", required=True, type=Path)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--git-repo", required=True, type=Path)
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID"))
    parser.add_argument(
        "--run-attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT")
    )
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument(
        "--workflow-sha", default=os.environ.get("GITHUB_WORKFLOW_SHA")
    )
    parser.add_argument(
        "--github-output", type=Path, default=os.environ.get("GITHUB_OUTPUT")
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(
    argv: Sequence[str] | None = None,
    *,
    transport: trust.ReadOnlyTransport | None = None,
) -> int:
    args = parse_args(argv)
    try:
        decision = authorize_desktop_release_dispatch(
            event_path=args.event,
            repository=args.repository,
            git_repo=args.git_repo,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            sha=args.sha,
            workflow_sha=args.workflow_sha,
            transport=transport,
        )
    except KeyboardInterrupt:
        return 130

    if decision.authorized:
        if args.github_output is None:
            decision = trust.Decision(
                "REFUSE",
                trust.Refusal.ARGUMENT_INVALID,
                _SAFE_REFUSAL_DETAIL,
            )
        else:
            try:
                write_github_output(args.github_output, decision.facts)
            except trust.ReleaseRefusal as exc:
                decision = trust.Decision(
                    "REFUSE", exc.reason, _SAFE_REFUSAL_DETAIL
                )
            except Exception:
                decision = trust.Decision(
                    "REFUSE",
                    trust.Refusal.INTERNAL_ERROR,
                    _SAFE_REFUSAL_DETAIL,
                )

    if args.json:
        print(
            json.dumps(
                {
                    "decision": decision.decision,
                    "reason": decision.reason.value,
                },
                sort_keys=True,
            )
        )
    else:
        print(f"{decision.decision} {decision.reason.value}")
    return 0 if decision.authorized else 1


if __name__ == "__main__":
    sys.exit(main())
