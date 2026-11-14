#!/usr/bin/env python3
"""Read-only authorization gate for a Locklark desktop release tag.

This is a preparatory source-only checkpoint. It is not wired into the
release workflow and it does not create, change, or prove any external GitHub
policy. It answers one question: may this exact workflow_run be bound to this
exact tag commit, and is that commit already contained in the trusted default
branch under the required external policy metadata?

The validator:

* reads a GitHub-generated ``workflow_run`` event and the canonical run API
  object, requiring the same repository id/name, run id, workflow id, exact
  workflow path, ``push`` event, completed successful conclusion, and head
  SHA;
* resolves only the exact local ``refs/tags/<tag>`` ref, accepting a
  lightweight or one-level annotated tag, and peels it by reading the real tag
  object—not by checking out the tag or executing any file in it;
* obtains the trusted default-branch tip from the read-only branch API and
  proves the tag commit is an ancestor of that real local git object with
  ``git merge-base --is-ancestor``;
* requires metadata proving main is protected with required checks, admin
  enforcement, and no force pushes/deletions; an active tag ruleset covering
  ``refs/tags/v*`` with deletion, update, and non-fast-forward rules and no
  untrusted bypass; a production environment restricted to the default branch;
  and production updater/signing secret names only at environment scope.

All API access is through an injectable read-only transport. The production
transport invokes only ``gh api --method GET`` for an explicit endpoint
allowlist. It never reads secret values, never writes or dispatches, never
checks out or executes tag content, and never trusts CI-reported artifacts in
place of API metadata.

Every refusal has a fixed enum value. Missing, malformed, unreadable, or
unknown metadata fails closed. See ``docs/release-trust.md`` for the external
prerequisites and the source-only status.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Mapping, Protocol, Sequence


RELEASE_WORKFLOW_PATH = ".github/workflows/release.yml"
DEFAULT_BRANCH = "main"
PRODUCTION_ENVIRONMENT = "production"

# These are the production credentials required by the current release
# workflow. The Windows pair is optional today, but if it exists anywhere it
# must still be environment-scoped rather than repository/org-scoped.
REQUIRED_ENVIRONMENT_SECRETS = frozenset(
    {
        "MYGO_UPDATER_PRIVATE_KEY",
        "MACOS_CERTIFICATE",
        "MACOS_CERTIFICATE_PASSWORD",
        "MACOS_SIGNING_IDENTITY",
        "MACOS_PROVISIONING_PROFILE",
        "APPLE_ID",
        "APPLE_TEAM_ID",
        "APPLE_APP_PASSWORD",
    }
)
OPTIONAL_PRODUCTION_SECRETS = frozenset(
    {
        "WINDOWS_CERTIFICATE",
        "WINDOWS_CERTIFICATE_PASSWORD",
    }
)
PRODUCTION_SECRETS = REQUIRED_ENVIRONMENT_SECRETS | OPTIONAL_PRODUCTION_SECRETS

REQUIRED_TAG_RULES = frozenset({"deletion", "update", "non_fast_forward"})
# Classic-main policy is app-bound. 15368 is the public GitHub Actions app id;
# a context listed only by name, or bound to any other app, is not trusted.
REQUIRED_STATUS_CHECK_CONTEXT = "ci-required"
GITHUB_ACTIONS_APP_ID = 15368
# Organization administrators are the only bypass class treated as trusted.
# Integrations, teams, users, and repository roles are not trusted to rewrite
# release tags. An empty bypass list is also accepted.
TRUSTED_BYPASS_ACTOR_TYPES = frozenset({"OrganizationAdmin"})
TAG_REF_PATTERN = "refs/tags/v*"

_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_TAG_RE = re.compile(
    r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
    r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# The production transport can read only these metadata shapes. In particular
# a secret value endpoint (``/secrets/<name>``) and every write/dispatch route
# are absent from this allowlist.
_API_ENDPOINT_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
        r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+$",
        r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/branches/main$",
        r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/branches/main/protection$",
        r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/rulesets(?:\?[A-Za-z0-9_=&.-]+)?$",
        r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/rulesets/[0-9]+(?:\?[A-Za-z0-9_=&.-]+)?$",
        r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/environments/production$",
        r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/environments/production/"
        r"deployment-branch-policies(?:\?[A-Za-z0-9_=&.-]+)?$",
        r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/environments/production/"
        r"secrets(?:\?[A-Za-z0-9_=&.-]+)?$",
        r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/secrets(?:\?[A-Za-z0-9_=&.-]+)?$",
        r"^/orgs/[A-Za-z0-9_.-]+/actions/secrets(?:\?[A-Za-z0-9_=&.-]+)?$",
    )
)

# ``gh api --paginate --slurp`` emits one entry per page. Repository rulesets
# use an array page, while deployment branch policies and secret listings use a
# ``{total_count, <key>: [...]}`` wrapper. A ``None`` key means array pages.
_LIST_ENDPOINT_KEYS: tuple[tuple[re.Pattern[str], str | None], ...] = tuple(
    (re.compile(pattern), key)
    for pattern, key in (
        (
            r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/rulesets"
            r"(?:\?[A-Za-z0-9_=&.-]+)?$",
            None,
        ),
        (
            r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/environments/production/"
            r"deployment-branch-policies(?:\?[A-Za-z0-9_=&.-]+)?$",
            "branch_policies",
        ),
        (
            r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/environments/production/"
            r"secrets(?:\?[A-Za-z0-9_=&.-]+)?$",
            "secrets",
        ),
        (
            r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/secrets"
            r"(?:\?[A-Za-z0-9_=&.-]+)?$",
            "secrets",
        ),
        (
            r"^/orgs/[A-Za-z0-9_.-]+/actions/secrets"
            r"(?:\?[A-Za-z0-9_=&.-]+)?$",
            "secrets",
        ),
    )
)


class Refusal(str, Enum):
    """Fixed refusal vocabulary. No free-form reason is returned."""

    AUTHORIZED = "authorized"

    ARGUMENT_INVALID = "argument_invalid"
    INTERNAL_ERROR = "internal_error"

    EVENT_ABSENT = "event_absent"
    EVENT_UNREADABLE = "event_unreadable"
    EVENT_INVALID = "event_invalid"

    REPOSITORY_INVALID = "repository_invalid"
    REPOSITORY_ABSENT = "repository_absent"
    REPOSITORY_UNREADABLE = "repository_unreadable"
    REPOSITORY_UNKNOWN = "repository_unknown"
    REPOSITORY_MISMATCH = "repository_mismatch"

    WORKFLOW_RUN_ABSENT = "workflow_run_absent"
    WORKFLOW_RUN_UNREADABLE = "workflow_run_unreadable"
    WORKFLOW_RUN_UNKNOWN = "workflow_run_unknown"
    WORKFLOW_RUN_MISMATCH = "workflow_run_mismatch"
    WORKFLOW_RUN_NOT_PUSH = "workflow_run_not_push"
    WORKFLOW_RUN_NOT_SUCCESS = "workflow_run_not_success"
    WORKFLOW_RUN_PATH_UNTRUSTED = "workflow_run_path_untrusted"
    WORKFLOW_RUN_REPOSITORY_MISMATCH = "workflow_run_repository_mismatch"
    WORKFLOW_RUN_HEAD_SHA_INVALID = "workflow_run_head_sha_invalid"

    DEFAULT_BRANCH_UNTRUSTED = "default_branch_untrusted"
    DEFAULT_BRANCH_ABSENT = "default_branch_absent"
    DEFAULT_BRANCH_UNREADABLE = "default_branch_unreadable"
    DEFAULT_BRANCH_UNKNOWN = "default_branch_unknown"
    DEFAULT_BRANCH_UNPROTECTED = "default_branch_unprotected"
    DEFAULT_BRANCH_OBJECT_MISSING = "default_branch_object_missing"

    BRANCH_PROTECTION_ABSENT = "branch_protection_absent"
    BRANCH_PROTECTION_UNREADABLE = "branch_protection_unreadable"
    BRANCH_PROTECTION_UNKNOWN = "branch_protection_unknown"
    BRANCH_PROTECTION_INSUFFICIENT = "branch_protection_insufficient"

    TAG_RULES_ABSENT = "tag_rules_absent"
    TAG_RULES_UNREADABLE = "tag_rules_unreadable"
    TAG_RULES_UNKNOWN = "tag_rules_unknown"
    TAG_RULES_INSUFFICIENT = "tag_rules_insufficient"
    TAG_RULES_BYPASS_UNTRUSTED = "tag_rules_bypass_untrusted"

    ENVIRONMENT_ABSENT = "environment_absent"
    ENVIRONMENT_UNREADABLE = "environment_unreadable"
    ENVIRONMENT_UNKNOWN = "environment_unknown"
    ENVIRONMENT_INSUFFICIENT = "environment_insufficient"

    BRANCH_POLICIES_ABSENT = "branch_policies_absent"
    BRANCH_POLICIES_UNREADABLE = "branch_policies_unreadable"
    BRANCH_POLICIES_UNKNOWN = "branch_policies_unknown"
    BRANCH_POLICIES_INSUFFICIENT = "branch_policies_insufficient"

    SECRETS_ENVIRONMENT_ABSENT = "secrets_environment_absent"
    SECRETS_ENVIRONMENT_UNREADABLE = "secrets_environment_unreadable"
    SECRETS_ENVIRONMENT_UNKNOWN = "secrets_environment_unknown"
    SECRETS_ENVIRONMENT_MISSING = "secrets_environment_missing"
    SECRETS_REPOSITORY_ABSENT = "secrets_repository_absent"
    SECRETS_REPOSITORY_UNREADABLE = "secrets_repository_unreadable"
    SECRETS_REPOSITORY_UNKNOWN = "secrets_repository_unknown"
    SECRETS_ORGANIZATION_ABSENT = "secrets_organization_absent"
    SECRETS_ORGANIZATION_UNREADABLE = "secrets_organization_unreadable"
    SECRETS_ORGANIZATION_UNKNOWN = "secrets_organization_unknown"
    SECRETS_REPOSITORY_LEAK = "secrets_repository_leak"
    SECRETS_ORGANIZATION_LEAK = "secrets_organization_leak"

    TAG_INVALID = "tag_invalid"
    TAG_MISSING = "tag_missing"
    TAG_AMBIGUOUS = "tag_ambiguous"
    TAG_UNREADABLE = "tag_unreadable"
    TAG_COMMIT_MISMATCH = "tag_commit_mismatch"

    GIT_REPOSITORY_INVALID = "git_repository_invalid"
    GIT_UNAVAILABLE = "git_unavailable"
    GIT_UNKNOWN = "git_unknown"
    CANDIDATE_NOT_ANCESTOR = "candidate_not_ancestor"
    ANCESTRY_UNKNOWN = "ancestry_unknown"


@dataclass(frozen=True)
class Decision:
    """The validator's complete public answer."""

    decision: str
    reason: Refusal
    detail: str
    facts: Mapping[str, object] = field(default_factory=dict)

    @property
    def authorized(self) -> bool:
        return self.decision == "AUTHORIZE"

    def as_json(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "reason": self.reason.value,
            "detail": self.detail,
            "facts": dict(self.facts),
        }


@dataclass(frozen=True)
class ApiResponse:
    status: int
    payload: object


class ApiTransportError(Exception):
    """A transport failure without exposing response bodies or credentials."""

    def __init__(self, status: int | None, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class UnsafeEndpoint(ValueError):
    """Raised before the production transport can issue a non-metadata GET."""


class ReadOnlyTransport(Protocol):
    def get(self, path: str) -> ApiResponse:
        ...

    def get_list(self, path: str) -> ApiResponse:
        ...


def validate_readonly_endpoint(path: str) -> None:
    """Reject anything outside the fixed, read-only metadata allowlist."""

    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or any(ord(character) < 0x20 or character.isspace() for character in path)
        or ".." in path
        or "\\" in path
        or "%" in path
    ):
        raise UnsafeEndpoint("invalid API endpoint")
    if not any(pattern.fullmatch(path) for pattern in _API_ENDPOINT_PATTERNS):
        raise UnsafeEndpoint("API endpoint is not in the read-only metadata allowlist")


def _paged(path: str) -> str:
    return f"{path}&per_page=100" if "?" in path else f"{path}?per_page=100"


def repository_api(repository: str) -> str:
    return f"/repos/{repository}"


def workflow_run_api(repository: str, run_id: int) -> str:
    return f"/repos/{repository}/actions/runs/{run_id}"


def branch_api(repository: str, branch: str = DEFAULT_BRANCH) -> str:
    return f"/repos/{repository}/branches/{branch}"


def branch_protection_api(repository: str, branch: str = DEFAULT_BRANCH) -> str:
    return f"/repos/{repository}/branches/{branch}/protection"


def rulesets_api(repository: str) -> str:
    return _paged(
        f"/repos/{repository}/rulesets?includes_parents=true&targets=tag"
    )


def ruleset_api(repository: str, ruleset_id: int) -> str:
    return f"/repos/{repository}/rulesets/{ruleset_id}?includes_parents=true"


def environment_api(
    repository: str, environment: str = PRODUCTION_ENVIRONMENT
) -> str:
    return f"/repos/{repository}/environments/{environment}"


def environment_branch_policies_api(
    repository: str, environment: str = PRODUCTION_ENVIRONMENT
) -> str:
    return _paged(
        f"/repos/{repository}/environments/{environment}/deployment-branch-policies"
    )


def environment_secrets_api(
    repository: str, environment: str = PRODUCTION_ENVIRONMENT
) -> str:
    return _paged(f"/repos/{repository}/environments/{environment}/secrets")


def repository_secrets_api(repository: str) -> str:
    return _paged(f"/repos/{repository}/actions/secrets")


def organization_secrets_api(organization: str) -> str:
    return _paged(f"/orgs/{organization}/actions/secrets")


def _paginated_list_key(path: str) -> str | None:
    """Return the expected page list key, or ``None`` for array pages."""

    for pattern, key in _LIST_ENDPOINT_KEYS:
        if pattern.fullmatch(path):
            return key
    raise UnsafeEndpoint("API endpoint does not support paginated list reads")


def _reject_duplicate_page_identities(items: Sequence[object], key: str | None) -> None:
    """Reject duplicate endpoint-specific identities without echoing values."""

    if key == "secrets":
        field = "name"
        label = "secret names"
    elif key == "branch_policies":
        field = "id"
        label = "branch policy ids"
    else:
        field = "id"
        label = "ruleset ids"
    seen: set[object] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get(field)
        if field == "id":
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                continue
        elif not isinstance(value, str) or not value:
            continue
        if value in seen:
            raise ApiTransportError(
                None, f"trusted gh api pagination contains duplicate {label}"
            )
        seen.add(value)


def _merge_slurped_pages(payload: object, key: str | None) -> list[object]:
    """Flatten real slurped pages after validating their endpoint schema."""

    if not isinstance(payload, list):
        raise ApiTransportError(None, "trusted gh api pagination shape is invalid")
    merged: list[object] = []
    if key is None:
        for page in payload:
            if not isinstance(page, list):
                raise ApiTransportError(
                    None, "trusted gh api pagination page is invalid"
                )
            merged.extend(page)
        _reject_duplicate_page_identities(merged, key)
        return merged

    reported_total: int | None = None
    for index, page in enumerate(payload):
        if not isinstance(page, dict) or set(page) != {"total_count", key}:
            raise ApiTransportError(None, "trusted gh api pagination page is invalid")
        total = page.get("total_count")
        items = page.get(key)
        if (
            isinstance(total, bool)
            or not isinstance(total, int)
            or total < 0
            or not isinstance(items, list)
            or total < len(items)
        ):
            raise ApiTransportError(None, "trusted gh api pagination page is invalid")
        if reported_total is None:
            reported_total = total
        elif total != reported_total:
            raise ApiTransportError(
                None, "trusted gh api pagination totals disagree"
            )
        if index > 0 and len(merged) >= reported_total:
            raise ApiTransportError(
                None, "trusted gh api pagination contains an extra page"
            )
        merged.extend(items)
    if reported_total is None or len(merged) != reported_total:
        raise ApiTransportError(None, "trusted gh api pagination count is incomplete")
    _reject_duplicate_page_identities(merged, key)
    return merged


class GhApiTransport:
    """Production transport: ``gh api --method GET`` only, fixed allowlist."""

    def __init__(self, executable: str = "gh", timeout: int = 30) -> None:
        self.executable = executable
        self.timeout = timeout

    def get(self, path: str) -> ApiResponse:
        return self._run(path, paginate=False)

    def get_list(self, path: str) -> ApiResponse:
        return self._run(path, paginate=True)

    def _run(self, path: str, *, paginate: bool) -> ApiResponse:
        validate_readonly_endpoint(path)
        list_key = _paginated_list_key(path) if paginate else None
        command = [self.executable, "api", "--method", "GET"]
        if paginate:
            command.extend(["--paginate", "--slurp"])
        command.extend(
            [
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
                path,
            ]
        )
        environment = os.environ.copy()
        environment["GH_PROMPT_DISABLED"] = "1"
        environment.setdefault("NO_COLOR", "1")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.timeout,
                env=environment,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ApiTransportError(None, "trusted gh executable unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            raise ApiTransportError(None, "trusted gh api read timed out") from exc
        except OSError as exc:
            raise ApiTransportError(None, "trusted gh api read failed") from exc

        if result.returncode != 0:
            match = re.search(r"HTTP ([0-9]{3})", result.stderr or "")
            status = int(match.group(1)) if match else None
            raise ApiTransportError(status, "trusted gh api GET was refused")
        try:
            payload = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ApiTransportError(None, "trusted gh api returned invalid JSON") from exc
        if paginate:
            payload = _merge_slurped_pages(payload, list_key)
        return ApiResponse(200, payload)


class ReleaseRefusal(Exception):
    """Internal control-flow exception carrying a fixed enum refusal."""

    def __init__(self, reason: Refusal, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _refuse(reason: Refusal, detail: str) -> None:
    raise ReleaseRefusal(reason, detail)


def _mapping(value: object, reason: Refusal, detail: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        _refuse(reason, detail)
    return value


def _positive_int(value: object, reason: Refusal, detail: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _refuse(reason, detail)
    return value


def _sha(value: object, reason: Refusal, detail: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        _refuse(reason, detail)
    return value


def _workflow_path(value: object, reason: Refusal) -> str:
    if not isinstance(value, str) or not value:
        _refuse(reason, "workflow path metadata is absent")
    base = value.split("@", 1)[0]
    if base != RELEASE_WORKFLOW_PATH:
        _refuse(
            Refusal.WORKFLOW_RUN_PATH_UNTRUSTED,
            "workflow_run does not name the exact release workflow path",
        )
    return base


def _api_call(
    transport: ReadOnlyTransport,
    path: str,
    *,
    list_response: bool,
    absent: Refusal,
    unreadable: Refusal,
    unknown: Refusal,
) -> object:
    try:
        response = (
            transport.get_list(path) if list_response else transport.get(path)
        )
    except ApiTransportError as exc:
        if exc.status == 404:
            _refuse(absent, f"metadata endpoint is absent (HTTP 404): {path}")
        if exc.status in (401, 403):
            _refuse(
                unreadable,
                f"metadata endpoint is unreadable (HTTP {exc.status}): {path}",
            )
        _refuse(unknown, f"metadata endpoint is unknown: {path}")
    except Exception:
        # An injected transport must fail closed without leaking details.
        _refuse(unknown, f"metadata endpoint is unknown: {path}")
    if not isinstance(response, ApiResponse):
        _refuse(unknown, f"metadata endpoint returned an invalid response: {path}")
    if response.status == 404:
        _refuse(absent, f"metadata endpoint is absent (HTTP 404): {path}")
    if response.status in (401, 403):
        _refuse(
            unreadable,
            f"metadata endpoint is unreadable (HTTP {response.status}): {path}",
        )
    if response.status != 200:
        _refuse(unknown, f"metadata endpoint is unknown (HTTP {response.status}): {path}")
    if response.payload is None:
        _refuse(unknown, f"metadata endpoint returned no body: {path}")
    return response.payload


def _list_items(
    payload: object,
    *,
    key: str | None,
    reason: Refusal,
    detail: str,
) -> Sequence[object]:
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        value = payload.get(key) if key is not None else None
        if not isinstance(value, list):
            _refuse(reason, detail)
        items = value
    else:
        _refuse(reason, detail)
    if isinstance(payload, dict):
        total = payload.get("total_count")
        if total is not None:
            if (
                isinstance(total, bool)
                or not isinstance(total, int)
                or total != len(items)
            ):
                _refuse(reason, detail)
    return items


def _load_event(event_path: Path) -> object:
    try:
        raw = event_path.read_bytes()
    except FileNotFoundError:
        _refuse(Refusal.EVENT_ABSENT, "GitHub workflow_run event is absent")
    except OSError:
        _refuse(Refusal.EVENT_UNREADABLE, "GitHub workflow_run event is unreadable")
    if len(raw) > 4 * 1024 * 1024:
        _refuse(Refusal.EVENT_UNREADABLE, "GitHub workflow_run event is too large")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        _refuse(Refusal.EVENT_UNREADABLE, "GitHub workflow_run event is not valid JSON")


@dataclass(frozen=True)
class EventBinding:
    action: str
    run_id: int
    workflow_id: int
    workflow_path: str
    event: str
    status: str
    conclusion: str
    head_sha: str
    head_branch_hint: str | None
    repository_id: int
    repository_full_name: str
    run_repository_id: int
    run_repository_full_name: str
    head_repository_id: int
    head_repository_full_name: str
    run_attempt: int | None


def _parse_event(event: object) -> EventBinding:
    event = _mapping(
        event, Refusal.EVENT_INVALID, "GitHub workflow_run event is not an object"
    )
    action = event.get("action")
    if action != "completed":
        _refuse(
            Refusal.WORKFLOW_RUN_NOT_SUCCESS,
            "workflow_run event action is not completed",
        )
    repository = _mapping(
        event.get("repository"),
        Refusal.EVENT_INVALID,
        "workflow_run event has no repository",
    )
    run = _mapping(
        event.get("workflow_run"),
        Refusal.EVENT_INVALID,
        "workflow_run event has no workflow_run object",
    )
    run_repository = _mapping(
        run.get("repository"),
        Refusal.EVENT_INVALID,
        "workflow_run event has no run repository",
    )
    head_repository = _mapping(
        run.get("head_repository"),
        Refusal.EVENT_INVALID,
        "workflow_run event has no head repository",
    )
    head_branch = run.get("head_branch")
    if head_branch is not None and not isinstance(head_branch, str):
        _refuse(
            Refusal.EVENT_INVALID,
            "workflow_run head_branch hint has an invalid type",
        )
    run_attempt = run.get("run_attempt")
    if run_attempt is not None:
        run_attempt = _positive_int(
            run_attempt,
            Refusal.EVENT_INVALID,
            "workflow_run run_attempt is invalid",
        )
    binding = EventBinding(
        action=action,
        run_id=_positive_int(
            run.get("id"), Refusal.EVENT_INVALID, "workflow_run id is invalid"
        ),
        workflow_id=_positive_int(
            run.get("workflow_id"),
            Refusal.EVENT_INVALID,
            "workflow_run workflow_id is invalid",
        ),
        workflow_path=_workflow_path(
            run.get("path"), Refusal.WORKFLOW_RUN_PATH_UNTRUSTED
        ),
        event=_text(
            run.get("event"), Refusal.EVENT_INVALID, "workflow_run event is invalid"
        ),
        status=_text(
            run.get("status"), Refusal.EVENT_INVALID, "workflow_run status is invalid"
        ),
        conclusion=_text(
            run.get("conclusion"),
            Refusal.EVENT_INVALID,
            "workflow_run conclusion is invalid",
        ),
        head_sha=_sha(
            run.get("head_sha"),
            Refusal.WORKFLOW_RUN_HEAD_SHA_INVALID,
            "workflow_run head_sha is invalid",
        ),
        head_branch_hint=head_branch,
        repository_id=_positive_int(
            repository.get("id"),
            Refusal.EVENT_INVALID,
            "event repository id is invalid",
        ),
        repository_full_name=_text(
            repository.get("full_name"),
            Refusal.EVENT_INVALID,
            "event repository full_name is invalid",
        ),
        run_repository_id=_positive_int(
            run_repository.get("id"),
            Refusal.EVENT_INVALID,
            "run repository id is invalid",
        ),
        run_repository_full_name=_text(
            run_repository.get("full_name"),
            Refusal.EVENT_INVALID,
            "run repository full_name is invalid",
        ),
        head_repository_id=_positive_int(
            head_repository.get("id"),
            Refusal.EVENT_INVALID,
            "head repository id is invalid",
        ),
        head_repository_full_name=_text(
            head_repository.get("full_name"),
            Refusal.EVENT_INVALID,
            "head repository full_name is invalid",
        ),
        run_attempt=run_attempt,
    )
    if binding.event != "push":
        _refuse(Refusal.WORKFLOW_RUN_NOT_PUSH, "workflow_run was not triggered by push")
    if binding.status != "completed" or binding.conclusion != "success":
        _refuse(
            Refusal.WORKFLOW_RUN_NOT_SUCCESS,
            "workflow_run is not a completed successful run",
        )
    return binding


def _text(value: object, reason: Refusal, detail: str) -> str:
    if not isinstance(value, str) or not value:
        _refuse(reason, detail)
    return value


@dataclass(frozen=True)
class RepositoryInfo:
    repository_id: int
    full_name: str
    default_branch: str
    owner_login: str
    owner_type: str


def _repository_info(payload: object, requested: str) -> RepositoryInfo:
    data = _mapping(
        payload, Refusal.REPOSITORY_UNKNOWN, "repository metadata is not an object"
    )
    repository_id = _positive_int(
        data.get("id"), Refusal.REPOSITORY_UNKNOWN, "repository id is invalid"
    )
    full_name = _text(
        data.get("full_name"),
        Refusal.REPOSITORY_UNKNOWN,
        "repository full_name is invalid",
    )
    if full_name.casefold() != requested.casefold():
        _refuse(
            Refusal.REPOSITORY_MISMATCH,
            "repository metadata names a different repository",
        )
    default_branch = _text(
        data.get("default_branch"),
        Refusal.REPOSITORY_UNKNOWN,
        "repository default branch is invalid",
    )
    if default_branch != DEFAULT_BRANCH:
        _refuse(
            Refusal.DEFAULT_BRANCH_UNTRUSTED,
            f"repository default branch is not {DEFAULT_BRANCH}",
        )
    owner = _mapping(
        data.get("owner"),
        Refusal.REPOSITORY_UNKNOWN,
        "repository owner is invalid",
    )
    owner_login = _text(
        owner.get("login"),
        Refusal.REPOSITORY_UNKNOWN,
        "repository owner login is invalid",
    )
    owner_type = _text(
        owner.get("type"),
        Refusal.REPOSITORY_UNKNOWN,
        "repository owner type is invalid",
    )
    if owner_type not in ("User", "Organization"):
        _refuse(Refusal.REPOSITORY_UNKNOWN, "repository owner type is unknown")
    return RepositoryInfo(
        repository_id=repository_id,
        full_name=full_name,
        default_branch=default_branch,
        owner_login=owner_login,
        owner_type=owner_type,
    )


def _bind_run(
    event: EventBinding,
    run_payload: object,
    repository: RepositoryInfo,
) -> Mapping[str, object]:
    run = _mapping(
        run_payload,
        Refusal.WORKFLOW_RUN_UNKNOWN,
        "workflow run metadata is not an object",
    )
    run_id = _positive_int(
        run.get("id"), Refusal.WORKFLOW_RUN_UNKNOWN, "workflow run id is invalid"
    )
    workflow_id = _positive_int(
        run.get("workflow_id"),
        Refusal.WORKFLOW_RUN_UNKNOWN,
        "workflow run workflow_id is invalid",
    )
    run_path = _workflow_path(run.get("path"), Refusal.WORKFLOW_RUN_PATH_UNTRUSTED)
    run_event = _text(
        run.get("event"), Refusal.WORKFLOW_RUN_UNKNOWN, "workflow run event is invalid"
    )
    run_status = _text(
        run.get("status"), Refusal.WORKFLOW_RUN_UNKNOWN, "workflow run status is invalid"
    )
    run_conclusion = _text(
        run.get("conclusion"),
        Refusal.WORKFLOW_RUN_UNKNOWN,
        "workflow run conclusion is invalid",
    )
    run_attempt = run.get("run_attempt")
    if run_attempt is not None:
        run_attempt = _positive_int(
            run_attempt,
            Refusal.WORKFLOW_RUN_UNKNOWN,
            "workflow run attempt is invalid",
        )
    run_head_sha = _sha(
        run.get("head_sha"),
        Refusal.WORKFLOW_RUN_HEAD_SHA_INVALID,
        "workflow run head_sha is invalid",
    )
    run_repository = _mapping(
        run.get("repository"),
        Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
        "workflow run has no repository",
    )
    head_repository = _mapping(
        run.get("head_repository"),
        Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
        "workflow run has no head repository",
    )
    run_repository_id = _positive_int(
        run_repository.get("id"),
        Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
        "workflow run repository id is invalid",
    )
    head_repository_id = _positive_int(
        head_repository.get("id"),
        Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
        "workflow run head repository id is invalid",
    )
    run_repository_name = _text(
        run_repository.get("full_name"),
        Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
        "workflow run repository name is invalid",
    )
    head_repository_name = _text(
        head_repository.get("full_name"),
        Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
        "workflow run head repository name is invalid",
    )

    if run_id != event.run_id:
        _refuse(Refusal.WORKFLOW_RUN_MISMATCH, "workflow run id differs from event")
    if workflow_id != event.workflow_id:
        _refuse(
            Refusal.WORKFLOW_RUN_MISMATCH,
            "workflow id differs between event and canonical run",
        )
    if run_path != event.workflow_path:
        _refuse(
            Refusal.WORKFLOW_RUN_PATH_UNTRUSTED,
            "workflow path differs between event and canonical run",
        )
    if run_event != event.event:
        _refuse(Refusal.WORKFLOW_RUN_MISMATCH, "workflow event differs from event body")
    if run_event != "push":
        _refuse(Refusal.WORKFLOW_RUN_NOT_PUSH, "canonical workflow run is not a push")
    if run_status != event.status:
        _refuse(
            Refusal.WORKFLOW_RUN_MISMATCH,
            "workflow status differs from event body",
        )
    if run_conclusion != event.conclusion:
        _refuse(
            Refusal.WORKFLOW_RUN_MISMATCH,
            "workflow conclusion differs from event body",
        )
    if run_status != "completed" or run_conclusion != "success":
        _refuse(
            Refusal.WORKFLOW_RUN_NOT_SUCCESS,
            "canonical workflow run is not completed successfully",
        )
    if run_head_sha != event.head_sha:
        _refuse(
            Refusal.WORKFLOW_RUN_MISMATCH,
            "workflow head SHA differs from event body",
        )
    if run_attempt is not None and event.run_attempt is not None:
        if run_attempt != event.run_attempt:
            _refuse(
                Refusal.WORKFLOW_RUN_MISMATCH,
                "workflow run attempt differs from event body",
            )
    if (
        event.repository_id != repository.repository_id
        or event.run_repository_id != repository.repository_id
        or event.head_repository_id != repository.repository_id
        or run_repository_id != repository.repository_id
        or head_repository_id != repository.repository_id
    ):
        _refuse(
            Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            "workflow_run repository ids do not match the canonical repository",
        )
    if (
        event.repository_full_name.casefold() != repository.full_name.casefold()
        or event.run_repository_full_name.casefold() != repository.full_name.casefold()
        or event.head_repository_full_name.casefold() != repository.full_name.casefold()
        or run_repository_name.casefold() != repository.full_name.casefold()
        or head_repository_name.casefold() != repository.full_name.casefold()
    ):
        _refuse(
            Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            "workflow_run repository names do not match the canonical repository",
        )
    return run


@dataclass(frozen=True)
class TagInfo:
    tag_object: str
    commit: str
    annotated: bool


class GitReader:
    """Read-only git object access. It never checks out or executes content."""

    def __init__(self, repository: Path, timeout: int = 30) -> None:
        self.repository = repository
        self.timeout = timeout
        self.environment = os.environ.copy()
        for name in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_NAMESPACE",
        ):
            self.environment.pop(name, None)
        for name in list(self.environment):
            if name.startswith("GIT_CONFIG_"):
                self.environment.pop(name, None)
        self.environment.update(
            {
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            }
        )

    def _git(self, *args: str, reason: Refusal = Refusal.GIT_UNKNOWN) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(self.repository), *args],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.timeout,
                env=self.environment,
                check=False,
            )
        except FileNotFoundError:
            _refuse(Refusal.GIT_UNAVAILABLE, "trusted git executable is unavailable")
        except subprocess.TimeoutExpired:
            _refuse(reason, "read-only git object access timed out")
        except OSError:
            _refuse(reason, "read-only git object access failed")
        if result.returncode != 0:
            _refuse(reason, "read-only git object access failed")
        try:
            return result.stdout
        except UnicodeError:
            _refuse(reason, "read-only git object output is not readable")

    def verify_repository(self) -> None:
        if not self.repository.is_dir():
            _refuse(Refusal.GIT_REPOSITORY_INVALID, "git repository path is not a directory")
        self._git("rev-parse", "--git-dir", reason=Refusal.GIT_REPOSITORY_INVALID)

    def _show_ref(self, ref: str, missing: Refusal) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(self.repository), "show-ref", "--verify", "--hash", ref],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.timeout,
                env=self.environment,
                check=False,
            )
        except FileNotFoundError:
            _refuse(Refusal.GIT_UNAVAILABLE, "trusted git executable is unavailable")
        except (subprocess.TimeoutExpired, OSError):
            _refuse(Refusal.GIT_UNKNOWN, "read-only git ref access failed")
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            _refuse(missing, "read-only git ref access failed")
        lines = result.stdout.splitlines()
        if len(lines) != 1:
            _refuse(Refusal.TAG_AMBIGUOUS, "tag ref resolved to multiple objects")
        object_id = lines[0].strip()
        if not _SHA_RE.fullmatch(object_id):
            _refuse(missing, "tag ref did not resolve to a full object id")
        return object_id

    def _object_type(self, object_id: str, reason: Refusal) -> str:
        output = self._git("cat-file", "-t", object_id, reason=reason).strip()
        if not output:
            _refuse(reason, "git object type is unavailable")
        return output

    def _tag_object(self, object_id: str) -> tuple[str, str, str]:
        raw = self._git(
            "cat-file", "tag", object_id, reason=Refusal.TAG_UNREADABLE
        ).encode("utf-8")
        header = raw.split(b"\n\n", 1)[0]
        if len(header) > 64 * 1024:
            _refuse(Refusal.TAG_INVALID, "annotated tag header is too large")
        fields: dict[str, str] = {}
        for line in header.split(b"\n"):
            if not line:
                continue
            if line.startswith(b" "):
                # Continuation lines belong to optional tagger/signature
                # metadata and are not needed for object binding.
                continue
            key, separator, value = line.partition(b" ")
            if not separator:
                _refuse(Refusal.TAG_INVALID, "annotated tag header is malformed")
            try:
                name = key.decode("ascii", errors="strict")
                decoded_value = value.decode("utf-8", errors="strict")
            except UnicodeError:
                _refuse(
                    Refusal.TAG_INVALID,
                    "annotated tag header is not valid text",
                )
            if name in fields:
                _refuse(
                    Refusal.TAG_AMBIGUOUS,
                    "annotated tag contains a duplicate binding field",
                )
            fields[name] = decoded_value
        for required in ("object", "type", "tag"):
            if required not in fields:
                _refuse(
                    Refusal.TAG_INVALID,
                    f"annotated tag has no {required} binding field",
                )
        return fields["object"], fields["type"], fields["tag"]

    def resolve_tag(self, tag: str) -> TagInfo:
        ref = f"refs/tags/{tag}"
        object_id = self._show_ref(ref, Refusal.TAG_MISSING)
        if object_id is None:
            _refuse(Refusal.TAG_MISSING, "release tag is absent")
        object_type = self._object_type(object_id, Refusal.TAG_UNREADABLE)
        if object_type == "commit":
            return TagInfo(tag_object=object_id, commit=object_id, annotated=False)
        if object_type != "tag":
            _refuse(Refusal.TAG_INVALID, "release tag points to a non-commit object")
        target_id, declared_type, declared_tag = self._tag_object(object_id)
        if not _SHA_RE.fullmatch(target_id):
            _refuse(Refusal.TAG_INVALID, "annotated tag target is not a full object id")
        if declared_tag != tag:
            _refuse(
                Refusal.TAG_INVALID,
                "annotated tag name differs from the exact release ref",
            )
        actual_type = self._object_type(target_id, Refusal.TAG_UNREADABLE)
        if declared_type != actual_type:
            _refuse(Refusal.TAG_INVALID, "annotated tag type does not match its target")
        if actual_type == "tag":
            _refuse(
                Refusal.TAG_AMBIGUOUS,
                "nested annotated release tag is not an exact tag commit",
            )
        if actual_type != "commit":
            _refuse(Refusal.TAG_INVALID, "annotated tag target is not a commit")
        return TagInfo(tag_object=object_id, commit=target_id, annotated=True)

    def ensure_commit(self, object_id: str, reason: Refusal) -> None:
        if self._object_type(object_id, reason) != "commit":
            _refuse(reason, "trusted default branch object is not a commit")

    def is_ancestor(self, candidate: str, descendant: str) -> bool:
        try:
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.repository),
                    "merge-base",
                    "--is-ancestor",
                    candidate,
                    descendant,
                ],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.timeout,
                env=self.environment,
                check=False,
            )
        except FileNotFoundError:
            _refuse(Refusal.GIT_UNAVAILABLE, "trusted git executable is unavailable")
        except (subprocess.TimeoutExpired, OSError):
            _refuse(Refusal.ANCESTRY_UNKNOWN, "read-only git ancestry check failed")
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        _refuse(
            Refusal.ANCESTRY_UNKNOWN,
            "read-only git ancestry check could not read the real objects",
        )
        raise AssertionError("unreachable")


def _check_branch(
    transport: ReadOnlyTransport,
    repository: str,
) -> str:
    branch_payload = _api_call(
        transport,
        branch_api(repository),
        list_response=False,
        absent=Refusal.DEFAULT_BRANCH_ABSENT,
        unreadable=Refusal.DEFAULT_BRANCH_UNREADABLE,
        unknown=Refusal.DEFAULT_BRANCH_UNKNOWN,
    )
    branch = _mapping(
        branch_payload,
        Refusal.DEFAULT_BRANCH_UNKNOWN,
        "default branch metadata is not an object",
    )
    if branch.get("name") != DEFAULT_BRANCH:
        _refuse(
            Refusal.DEFAULT_BRANCH_UNTRUSTED,
            "default branch metadata does not name main",
        )
    if branch.get("protected") is not True:
        _refuse(
            Refusal.DEFAULT_BRANCH_UNPROTECTED,
            "canonical default branch is not protected",
        )
    commit = _mapping(
        branch.get("commit"),
        Refusal.DEFAULT_BRANCH_UNKNOWN,
        "default branch commit metadata is invalid",
    )
    return _sha(
        commit.get("sha"),
        Refusal.DEFAULT_BRANCH_UNKNOWN,
        "default branch commit SHA is invalid",
    )


def _check_required_status_checks(protection: Mapping[str, object]) -> None:
    checks = protection.get("required_status_checks")
    if not isinstance(checks, dict):
        _refuse(
            Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            "main has no required status checks",
        )
    entries = checks.get("checks")
    if not isinstance(entries, list) or not entries:
        _refuse(
            Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            "main has no app-bound required status checks",
        )
    matching: list[Mapping[str, object]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            _refuse(
                Refusal.BRANCH_PROTECTION_INSUFFICIENT,
                "main required status check metadata is malformed",
            )
        context = entry.get("context")
        if not isinstance(context, str) or not context:
            _refuse(
                Refusal.BRANCH_PROTECTION_INSUFFICIENT,
                "main required status check context is malformed",
            )
        if context == REQUIRED_STATUS_CHECK_CONTEXT:
            matching.append(entry)
    if len(matching) != 1:
        _refuse(
            Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            f"main must require exactly one {REQUIRED_STATUS_CHECK_CONTEXT!r} check",
        )
    app_id = matching[0].get("app_id")
    if (
        isinstance(app_id, bool)
        or not isinstance(app_id, int)
        or app_id != GITHUB_ACTIONS_APP_ID
    ):
        _refuse(
            Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            "required status check is not bound to the expected GitHub Actions app",
        )


def _check_pull_request_reviews(protection: Mapping[str, object]) -> None:
    reviews = protection.get("required_pull_request_reviews")
    if not isinstance(reviews, dict):
        _refuse(
            Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            "main has no required pull request reviews",
        )
    count = reviews.get("required_approving_review_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        _refuse(
            Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            "main requires an invalid approving review count",
        )
    for field in ("dismiss_stale_reviews", "require_last_push_approval"):
        if reviews.get(field) is not True:
            _refuse(
                Refusal.BRANCH_PROTECTION_INSUFFICIENT,
                f"main review setting {field} is not enabled",
            )
    bypass = reviews.get("bypass_pull_request_allowances")
    if not isinstance(bypass, dict):
        _refuse(
            Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            "main review bypass metadata is absent or malformed",
        )
    expected = {"users", "teams", "apps"}
    if set(bypass) != expected:
        _refuse(
            Refusal.BRANCH_PROTECTION_INSUFFICIENT,
            "main review bypass metadata has unknown allowances",
        )
    for key in expected:
        value = bypass[key]
        if not isinstance(value, list) or value:
            _refuse(
                Refusal.BRANCH_PROTECTION_INSUFFICIENT,
                f"main review bypass allowance {key} is not empty",
            )


def _check_protection(transport: ReadOnlyTransport, repository: str) -> None:
    payload = _api_call(
        transport,
        branch_protection_api(repository),
        list_response=False,
        absent=Refusal.BRANCH_PROTECTION_ABSENT,
        unreadable=Refusal.BRANCH_PROTECTION_UNREADABLE,
        unknown=Refusal.BRANCH_PROTECTION_UNKNOWN,
    )
    protection = _mapping(
        payload,
        Refusal.BRANCH_PROTECTION_UNKNOWN,
        "branch protection metadata is not an object",
    )
    _check_required_status_checks(protection)
    _check_pull_request_reviews(protection)
    for field, expected in (
        ("enforce_admins", True),
        ("allow_force_pushes", False),
        ("allow_deletions", False),
    ):
        setting = protection.get(field)
        if not isinstance(setting, dict) or not isinstance(
            setting.get("enabled"), bool
        ):
            _refuse(
                Refusal.BRANCH_PROTECTION_INSUFFICIENT,
                f"main protection setting {field} is absent or malformed",
            )
        if setting["enabled"] is not expected:
            _refuse(
                Refusal.BRANCH_PROTECTION_INSUFFICIENT,
                f"main protection setting {field} is not fail-closed",
            )


def _covers_all_v_tags(detail: Mapping[str, object]) -> bool | None:
    """Return coverage, or None when the ruleset condition metadata is malformed."""

    conditions = detail.get("conditions")
    if not isinstance(conditions, dict):
        return None
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        return None
    includes = ref_name.get("include")
    excludes = ref_name.get("exclude", [])
    if not isinstance(includes, list) or not all(
        isinstance(item, str) for item in includes
    ):
        return None
    if not isinstance(excludes, list) or not all(
        isinstance(item, str) for item in excludes
    ):
        return None
    # An exclusion can carve a release tag out of otherwise immutable v* refs.
    if excludes:
        return False
    return any(item in (TAG_REF_PATTERN, "v*") for item in includes)


def _check_tag_rules(transport: ReadOnlyTransport, repository: str) -> None:
    payload = _api_call(
        transport,
        rulesets_api(repository),
        list_response=True,
        absent=Refusal.TAG_RULES_ABSENT,
        unreadable=Refusal.TAG_RULES_UNREADABLE,
        unknown=Refusal.TAG_RULES_UNKNOWN,
    )
    summaries = _list_items(
        payload,
        key="rulesets",
        reason=Refusal.TAG_RULES_UNKNOWN,
        detail="ruleset list metadata is malformed",
    )
    if not summaries:
        _refuse(Refusal.TAG_RULES_ABSENT, "repository has no tag rulesets")
    saw_tag_ruleset = False
    applicable_rules: set[str] = set()
    ruleset_ids: set[int] = set()
    for raw_summary in summaries:
        summary = _mapping(
            raw_summary,
            Refusal.TAG_RULES_UNKNOWN,
            "ruleset summary is malformed",
        )
        ruleset_id = _positive_int(
            summary.get("id"),
            Refusal.TAG_RULES_UNKNOWN,
            "ruleset id is malformed",
        )
        if ruleset_id in ruleset_ids:
            _refuse(
                Refusal.TAG_RULES_UNKNOWN,
                "ruleset list contains duplicate ids",
            )
        ruleset_ids.add(ruleset_id)
        detail_payload = _api_call(
            transport,
            ruleset_api(repository, ruleset_id),
            list_response=False,
            absent=Refusal.TAG_RULES_UNKNOWN,
            unreadable=Refusal.TAG_RULES_UNREADABLE,
            unknown=Refusal.TAG_RULES_UNKNOWN,
        )
        detail = _mapping(
            detail_payload,
            Refusal.TAG_RULES_UNKNOWN,
            "ruleset detail is malformed",
        )
        if (
            _positive_int(
                detail.get("id"),
                Refusal.TAG_RULES_UNKNOWN,
                "ruleset detail id is malformed",
            )
            != ruleset_id
        ):
            _refuse(
                Refusal.TAG_RULES_UNKNOWN,
                "ruleset detail id differs from the list entry",
            )
        target = detail.get("target")
        enforcement = detail.get("enforcement")
        if not isinstance(target, str) or not isinstance(enforcement, str):
            _refuse(
                Refusal.TAG_RULES_UNKNOWN,
                "ruleset target or enforcement metadata is malformed",
            )
        if target != "tag":
            continue
        saw_tag_ruleset = True
        coverage = _covers_all_v_tags(detail)
        if coverage is None:
            _refuse(
                Refusal.TAG_RULES_UNKNOWN,
                "tag ruleset ref conditions are absent or malformed",
            )
        if enforcement != "active" or not coverage:
            continue
        rules = detail.get("rules")
        if not isinstance(rules, list):
            _refuse(
                Refusal.TAG_RULES_UNKNOWN,
                "active tag ruleset rules metadata is malformed",
            )
        rule_types: set[str] = set()
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
                _refuse(
                    Refusal.TAG_RULES_UNKNOWN,
                    "active tag ruleset has a malformed rule",
                )
            rule_types.add(rule["type"])
        bypass_actors = detail.get("bypass_actors")
        if not isinstance(bypass_actors, list):
            _refuse(
                Refusal.TAG_RULES_UNKNOWN,
                "active tag ruleset bypass metadata is malformed",
            )
        for actor in bypass_actors:
            if not isinstance(actor, dict) or not isinstance(
                actor.get("actor_type"), str
            ):
                _refuse(
                    Refusal.TAG_RULES_UNKNOWN,
                    "active tag ruleset has a malformed bypass actor",
                )
            if actor["actor_type"] not in TRUSTED_BYPASS_ACTOR_TYPES:
                _refuse(
                    Refusal.TAG_RULES_BYPASS_UNTRUSTED,
                    "active tag ruleset allows a non-organization-admin bypass",
                )
        applicable_rules.update(rule_types)
    if not saw_tag_ruleset:
        _refuse(Refusal.TAG_RULES_ABSENT, "repository has no tag-targeted rulesets")
    missing = REQUIRED_TAG_RULES - applicable_rules
    if missing:
        _refuse(
            Refusal.TAG_RULES_INSUFFICIENT,
            "active v* tag ruleset is missing immutable tag rules: "
            + ", ".join(sorted(missing)),
        )


def _check_environment(
    transport: ReadOnlyTransport, repository: str
) -> tuple[Mapping[str, object], Sequence[object]]:
    payload = _api_call(
        transport,
        environment_api(repository),
        list_response=False,
        absent=Refusal.ENVIRONMENT_ABSENT,
        unreadable=Refusal.ENVIRONMENT_UNREADABLE,
        unknown=Refusal.ENVIRONMENT_UNKNOWN,
    )
    environment = _mapping(
        payload,
        Refusal.ENVIRONMENT_UNKNOWN,
        "environment metadata is not an object",
    )
    if environment.get("name") != PRODUCTION_ENVIRONMENT:
        _refuse(
            Refusal.ENVIRONMENT_UNKNOWN,
            "production environment metadata names a different environment",
        )
    policy = environment.get("deployment_branch_policy")
    if not isinstance(policy, dict):
        _refuse(
            Refusal.ENVIRONMENT_INSUFFICIENT,
            "production environment has no deployment branch policy",
        )
    if policy.get("custom_branch_policies") is not True or policy.get(
        "protected_branches"
    ) is not False:
        _refuse(
            Refusal.ENVIRONMENT_INSUFFICIENT,
            "production environment does not use a custom default-branch-only policy",
        )
    policies_payload = _api_call(
        transport,
        environment_branch_policies_api(repository),
        list_response=True,
        absent=Refusal.BRANCH_POLICIES_ABSENT,
        unreadable=Refusal.BRANCH_POLICIES_UNREADABLE,
        unknown=Refusal.BRANCH_POLICIES_UNKNOWN,
    )
    policies = _list_items(
        policies_payload,
        key="branch_policies",
        reason=Refusal.BRANCH_POLICIES_UNKNOWN,
        detail="deployment branch policy metadata is malformed",
    )
    names: list[str] = []
    policy_ids: set[int] = set()
    for item in policies:
        if not isinstance(item, dict):
            _refuse(
                Refusal.BRANCH_POLICIES_UNKNOWN,
                "deployment branch policy entry is malformed",
            )
        policy_id = _positive_int(
            item.get("id"),
            Refusal.BRANCH_POLICIES_UNKNOWN,
            "deployment branch policy id is malformed",
        )
        if policy_id in policy_ids:
            _refuse(
                Refusal.BRANCH_POLICIES_UNKNOWN,
                "deployment branch policy list contains duplicate ids",
            )
        policy_ids.add(policy_id)
        name = item.get("name")
        policy_type = item.get("type")
        if (
            not isinstance(name, str)
            or not name
            or policy_type not in ("branch", "tag")
        ):
            _refuse(
                Refusal.BRANCH_POLICIES_UNKNOWN,
                "deployment branch policy entry is malformed",
            )
        if policy_type != "branch":
            _refuse(
                Refusal.BRANCH_POLICIES_INSUFFICIENT,
                "production environment permits non-branch deployments",
            )
        if "*" in name or "?" in name:
            _refuse(
                Refusal.BRANCH_POLICIES_INSUFFICIENT,
                "production environment permits a wildcard deployment branch",
            )
        names.append(name)
    if names != [DEFAULT_BRANCH]:
        _refuse(
            Refusal.BRANCH_POLICIES_INSUFFICIENT,
            "production environment is not restricted exactly to main",
        )
    return environment, policies


def _secret_names(
    payload: object,
    *,
    reason: Refusal,
    label: str,
) -> set[str]:
    items = _list_items(
        payload,
        key="secrets",
        reason=reason,
        detail=f"{label} secret name metadata is malformed",
    )
    names: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            _refuse(reason, f"{label} secret name metadata is malformed")
        name = item["name"]
        if not name or name in names:
            _refuse(reason, f"{label} secret name metadata is malformed")
        names.add(name)
    return names


def _check_secrets(
    transport: ReadOnlyTransport,
    repository: str,
    repository_info: RepositoryInfo,
) -> None:
    payload = _api_call(
        transport,
        environment_secrets_api(repository),
        list_response=True,
        absent=Refusal.SECRETS_ENVIRONMENT_ABSENT,
        unreadable=Refusal.SECRETS_ENVIRONMENT_UNREADABLE,
        unknown=Refusal.SECRETS_ENVIRONMENT_UNKNOWN,
    )
    environment_names = _secret_names(
        payload, reason=Refusal.SECRETS_ENVIRONMENT_UNKNOWN, label="environment"
    )
    missing = REQUIRED_ENVIRONMENT_SECRETS - environment_names
    if missing:
        _refuse(
            Refusal.SECRETS_ENVIRONMENT_MISSING,
            "production environment is missing required updater/signing secrets: "
            + ", ".join(sorted(missing)),
        )

    repository_payload = _api_call(
        transport,
        repository_secrets_api(repository),
        list_response=True,
        absent=Refusal.SECRETS_REPOSITORY_ABSENT,
        unreadable=Refusal.SECRETS_REPOSITORY_UNREADABLE,
        unknown=Refusal.SECRETS_REPOSITORY_UNKNOWN,
    )
    repository_names = _secret_names(
        repository_payload,
        reason=Refusal.SECRETS_REPOSITORY_UNKNOWN,
        label="repository",
    )
    leaked = PRODUCTION_SECRETS & repository_names
    if leaked:
        _refuse(
            Refusal.SECRETS_REPOSITORY_LEAK,
            "production credentials must not be repository-scoped: "
            + ", ".join(sorted(leaked)),
        )

    if repository_info.owner_type == "Organization":
        organization_payload = _api_call(
            transport,
            organization_secrets_api(repository_info.owner_login),
            list_response=True,
            absent=Refusal.SECRETS_ORGANIZATION_ABSENT,
            unreadable=Refusal.SECRETS_ORGANIZATION_UNREADABLE,
            unknown=Refusal.SECRETS_ORGANIZATION_UNKNOWN,
        )
        organization_names = _secret_names(
            organization_payload,
            reason=Refusal.SECRETS_ORGANIZATION_UNKNOWN,
            label="organization",
        )
        leaked = PRODUCTION_SECRETS & organization_names
        if leaked:
            _refuse(
                Refusal.SECRETS_ORGANIZATION_LEAK,
                "production credentials must not be organization-scoped: "
                + ", ".join(sorted(leaked)),
            )


def _run_authorization(
    *,
    event: object,
    repository: str,
    tag: str,
    git_repo: Path,
    transport: ReadOnlyTransport,
) -> Mapping[str, object]:
    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository):
        _refuse(Refusal.REPOSITORY_INVALID, "repository must be owner/name")
    if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
        _refuse(Refusal.TAG_INVALID, "release tag must be an exact semantic v tag")

    binding = _parse_event(event)

    git = GitReader(git_repo)
    git.verify_repository()
    tag_info = git.resolve_tag(tag)
    if binding.repository_full_name.casefold() != repository.casefold():
        _refuse(
            Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            "workflow_run event belongs to a different repository",
        )

    repository_payload = _api_call(
        transport,
        repository_api(repository),
        list_response=False,
        absent=Refusal.REPOSITORY_ABSENT,
        unreadable=Refusal.REPOSITORY_UNREADABLE,
        unknown=Refusal.REPOSITORY_UNKNOWN,
    )
    repository_info = _repository_info(repository_payload, repository)
    if (
        binding.repository_id != repository_info.repository_id
        or binding.run_repository_id != repository_info.repository_id
        or binding.head_repository_id != repository_info.repository_id
    ):
        _refuse(
            Refusal.WORKFLOW_RUN_REPOSITORY_MISMATCH,
            "workflow_run repository id does not match canonical repository id",
        )

    run_payload = _api_call(
        transport,
        workflow_run_api(repository, binding.run_id),
        list_response=False,
        absent=Refusal.WORKFLOW_RUN_ABSENT,
        unreadable=Refusal.WORKFLOW_RUN_UNREADABLE,
        unknown=Refusal.WORKFLOW_RUN_UNKNOWN,
    )
    run = _bind_run(binding, run_payload, repository_info)
    canonical_head = _sha(
        run.get("head_sha"),
        Refusal.WORKFLOW_RUN_HEAD_SHA_INVALID,
        "canonical workflow run head_sha is invalid",
    )
    if canonical_head != tag_info.commit:
        _refuse(
            Refusal.TAG_COMMIT_MISMATCH,
            "workflow_run head SHA does not equal the exact real tag commit",
        )

    default_branch_sha = _check_branch(transport, repository)
    _check_protection(transport, repository)
    _check_tag_rules(transport, repository)
    _check_environment(transport, repository)
    _check_secrets(transport, repository, repository_info)

    git.ensure_commit(
        default_branch_sha, Refusal.DEFAULT_BRANCH_OBJECT_MISSING
    )
    if not git.is_ancestor(tag_info.commit, default_branch_sha):
        _refuse(
            Refusal.CANDIDATE_NOT_ANCESTOR,
            "tag commit is not an ancestor of the trusted protected default branch",
        )

    return {
        "repository": repository_info.full_name,
        "repository_id": repository_info.repository_id,
        "tag": tag,
        "tag_object": tag_info.tag_object,
        "tag_commit": tag_info.commit,
        "tag_annotated": tag_info.annotated,
        "workflow_run_id": binding.run_id,
        "workflow_id": binding.workflow_id,
        "head_branch_hint": binding.head_branch_hint,
        "default_branch": DEFAULT_BRANCH,
        "default_branch_commit": default_branch_sha,
        "environment": PRODUCTION_ENVIRONMENT,
        "required_tag_rules": sorted(REQUIRED_TAG_RULES),
        "production_secret_scope": "environment",
    }


def authorize_desktop_release(
    *,
    event: object | None = None,
    event_path: str | Path | None = None,
    repository: str,
    tag: str,
    git_repo: str | Path,
    transport: ReadOnlyTransport | None = None,
) -> Decision:
    """Return a fail-closed authorization decision.

    Tests inject a transport implementing ``get``/``get_list``. Production
    callers use the default ``GhApiTransport``, which can only issue explicit
    allowlisted ``gh api --method GET`` calls.
    """

    if event is not None and event_path is not None:
        return Decision(
            "REFUSE",
            Refusal.ARGUMENT_INVALID,
            "provide exactly one of event or event_path",
        )
    if not isinstance(git_repo, (str, os.PathLike)):
        return Decision(
            "REFUSE",
            Refusal.ARGUMENT_INVALID,
            "git_repo must be a filesystem path",
        )
    if event_path is not None and not isinstance(event_path, (str, os.PathLike)):
        return Decision(
            "REFUSE",
            Refusal.ARGUMENT_INVALID,
            "event_path must be a filesystem path",
        )
    if transport is None:
        transport = GhApiTransport()
    try:
        if event is None:
            if event_path is None:
                _refuse(Refusal.EVENT_ABSENT, "GitHub workflow_run event is absent")
            event = _load_event(Path(event_path))
        facts = _run_authorization(
            event=event,
            repository=repository,
            tag=tag,
            git_repo=Path(git_repo),
            transport=transport,
        )
    except ReleaseRefusal as exc:
        return Decision("REFUSE", exc.reason, exc.detail)
    return Decision(
        "AUTHORIZE",
        Refusal.AUTHORIZED,
        "workflow_run, exact tag commit, protected default branch ancestry, "
        "tag immutability, environment branch restriction, and credential "
        "scope metadata all satisfied",
        facts,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only preparatory release-trust authorization. This does not "
            "publish, write, fetch credentials, check out tags, or change policy."
        )
    )
    parser.add_argument("--event", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--git-repo", required=True, type=Path)
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the decision as machine-readable JSON",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        decision = authorize_desktop_release(
            event_path=args.event,
            repository=args.repository,
            tag=args.tag,
            git_repo=args.git_repo,
        )
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # pragma: no cover - fixed-enum safety net
        decision = Decision(
            "REFUSE",
            Refusal.INTERNAL_ERROR,
            f"unexpected validator failure: {type(exc).__name__}",
        )
    if args.json:
        print(json.dumps(decision.as_json(), sort_keys=True))
    else:
        print(f"{decision.decision} {decision.reason.value}: {decision.detail}")
    return 0 if decision.authorized else 1


if __name__ == "__main__":
    sys.exit(main())
