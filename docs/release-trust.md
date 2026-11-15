# Desktop release trust: preparatory checkpoint

`scripts/authorize_desktop_release.py` is a **source-only preparatory
checkpoint**. It is not invoked by the release workflow, does not publish or
build anything, and does not create, change, or prove the external GitHub
policy required for a trusted release. A successful local invocation is not a
release, a policy acceptance result, or evidence that the repository is safe
to release.

The validator is intentionally read-only:

- metadata is read through the trusted `gh api` client with
  `--method GET` only, or through an injected test transport;
- the production transport has a fixed endpoint allowlist and no write,
  dispatch, privilege, publish, or secret-value route;
- only secret **names** are inspected; values are never requested or printed;
- tag contents are read as git objects with `cat-file`; the tag is never
  checked out, extracted, or executed;
- a GitHub-generated `workflow_run` event is used only as an input hint. The
  canonical workflow-run and repository objects are fetched from the API and
  all binding fields must agree.

Every refusal is one of the fixed enum values in `Refusal` (for example
`workflow_run_mismatch`, `tag_commit_mismatch`,
`branch_protection_insufficient`, or `secrets_repository_leak`). Missing,
unreadable, malformed, and unknown metadata all fail closed; there is no
"best effort" or warning-only path.

## What a successful checkpoint verifies

1. The `workflow_run` event and canonical API run have the same repository
   id/name, run id, workflow id, the historical test workflow path,
   `push` event, completed `success` conclusion, and head SHA.
2. The canonical run API `actor.id` and `triggering_actor.id` are positive
   integers and each exactly equals the `owner.id` from the same canonical
   repository API response. `owner.id` is also a positive integer, and
   `owner.type` is `User`. Event actor hints and login strings are not
   trusted. This personal-repository policy refuses bots, collaborators, and
   organization-owned repositories; it does not define a shared or
   organization publishing model.
3. The exact local `refs/tags/<tag>` exists and resolves to the same commit.
   Lightweight tags and one-level annotated tags are supported. A missing
   tag, a retagged ref, a nested tag, or a tag object with ambiguous binding
   fields is refused.
4. The tag commit is an ancestor of the current protected default branch tip
   returned by the read-only branch API. The ancestry check uses the real
   local git object for the API tip with `git merge-base --is-ancestor`.
5. `main` is protected with required status checks, required pull-request
   reviews, admin enforcement, force pushes disabled, and deletions disabled.
   A present classic `bypass_pull_request_allowances` field must be explicitly
   empty. If the classic response omits that field, one single active canonical
   repository branch ruleset must independently prove an explicitly empty
   `bypass_actors` list and a `pull_request` rule at least as strict as the
   classic review count.
6. An active tag ruleset includes exactly `refs/tags/v*` and contains
   `deletion`, `update`, and `non_fast_forward` rules. Bare `v*`, broader
   patterns, extra include patterns, and exclusions are refused. Bypass
   actors are empty or `OrganizationAdmin`; every other bypass type is
   refused.
7. The `production` environment has a custom deployment branch policy that
   names exactly `main` and does not permit wildcards, extra branches, or tag
   deployments.
8. The required updater and macOS signing/notarization secret names exist in
   the `production` environment: `MYGO_UPDATER_PRIVATE_KEY`,
   `MACOS_CERTIFICATE`, `MACOS_CERTIFICATE_PASSWORD`,
   `MACOS_SIGNING_IDENTITY`, `MACOS_PROVISIONING_PROFILE`, `APPLE_ID`,
   `APPLE_TEAM_ID`, and `APPLE_APP_PASSWORD`. Production credential names
   (including the optional `WINDOWS_CERTIFICATE` and
   `WINDOWS_CERTIFICATE_PASSWORD` pair if present) must not exist at
   repository or organization scope.

### Scope limitation: ruleset bypass metadata may be invisible

The classic branch-protection GET examples may omit
`bypass_pull_request_allowances`. The validator does not infer an empty value
from that omission; it requires an independent canonical branch-ruleset proof.
GitHub may also omit or hide a ruleset's `bypass_actors` when the caller lacks
write access to that ruleset. The validator requires an explicitly present,
empty list. An invisible or missing field is refused, never treated as empty,
and the read-only credential is never widened to obtain write access. This
checkpoint proves only what the source metadata explicitly exposes; it makes no
claim that an unseen bypass policy does not exist.

### Scope limitation: `v*` tag-name squatting is not prevented

The canonical actor check refuses outsider publication, but it does **not**
prevent collaborators from creating or occupying unused `v*` tag names
(tag-name squatting or denial of service). The required `deletion`, `update`,
and `non_fast_forward` rules constrain movement of existing tags; they do not
constrain tag creation. This checkpoint makes no namespace anti-squatting
claim. Controlling who may create `v*` tags would require separate explicit
external policy and trust design and is not added here.

## Immutable external prerequisites

These prerequisites cannot be created by this checkpoint and are not fixed by
committing this source. They must already be immutable external facts before a
future release workflow is allowed to use this validator:

- the repository and owner ids, release workflow id/path, and tag are already
  fixed and cannot be rewritten by an untrusted actor;
- the repository is owned by the personal user whose positive `owner.id` both
  canonical run actor ids equal. Organization-owned repositories and bot
  initiators require a separate explicit trust design;
- `main` is protected and its protection settings are enforced for
  administrators;
- an active tag ruleset prevents deletion, updates, and non-fast-forward
  movement of every `v*` tag, with no untrusted bypass actor;
- the `production` environment restricts deployment to the default branch and
  holds the updater/signing credentials as environment secrets;
- repository and organization secret listings do not contain those production
  credential names;
- the runner has real local objects for the exact tag commit and the current
  default-branch tip. Shallow or missing objects are refused, not fetched;
- the tag and default branch are not retargeted between metadata reads and the
  ancestry check. The validator is a point-in-time checkpoint, not a
  continuous policy monitor;
- the trusted `gh` CLI is authenticated read-only for these metadata endpoints.
  This validator never creates a token or elevates permissions.

Bypass actors of type `OrganizationAdmin` are treated as trusted organization
administration. If that is not the intended trust model, remove that allowance
from source and configure the ruleset with no bypass actors. This choice is
explicit; it is not inferred from the repository.

## Illustrative unsafe-policy fixtures

The following fabricated examples illustrate metadata shapes that must be
refused. They are generic contract examples only: they do not describe this or
any other repository, any current deployment, or the actual location of any
credential.

- the default branch is unprotected, lacks required checks, permits force
  pushes or deletions, or does not enforce protection for administrators;
- the canonical run actor or triggering actor is missing, malformed, a bot,
  a collaborator, or has a different id than the repository owner id, even if
  an event actor hint or login string appears to match; the repository owner
  is not a personal `User`;
- the active tag ruleset does not include exactly `refs/tags/v*`, the active
  ruleset omits deletion, update, or non-fast-forward protection, or it allows
  a non-organization-admin bypass;
- the production environment is absent, has no deployment branch policy,
  permits a branch other than the default branch, or permits wildcards or tag
  deployments;
- a required production updater/signing credential name is absent from the
  environment scope, or the same name appears at repository or organization
  scope.

For every such fixture the validator refuses with a fixed enum. It never
repairs, grants, or claims that external policy has been fixed. The
fake-metadata tests described below are contract tests, not evidence of actual
GitHub policy acceptance.

## Usage and tests

The historical `workflow_run` CLI is deliberately not wired into the active
release workflow. The C2b workflow uses
`scripts/desktop_release_routing.py` for default-branch `repository_dispatch`
routing, as described in [release-routing.md](release-routing.md). The
historical CLI remains an unwired contract and would require a trusted event
path and a git repository containing the tag and default-branch objects, for
example:

```sh
python3 scripts/authorize_desktop_release.py \
  --event "$GITHUB_EVENT_PATH" \
  --repository "$GITHUB_REPOSITORY" \
  --tag v0.2.0 \
  --git-repo . \
  --json
```

The focused tests use a real temporary test-owned git repository for
lightweight tags, annotated tags, unreviewed candidates, missing/ambiguous
tags, and tag retargeting. They then exercise adversarial fake API metadata
for the policy and credential contracts. Run them with:

```sh
python3 -m unittest scripts/test_authorize_desktop_release.py
```

The fake metadata tests are contract tests, not actual GitHub policy
acceptance. No test creates a token, changes repository settings, checks out a
tag, or publishes anything.
