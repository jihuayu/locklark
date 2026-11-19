# Desktop release routing

This document describes the **source-only** routing contract used by the C2b
default-branch release workflow. The workflow is triggered only by a
`repository_dispatch` event; it does not dispatch a release itself, apply a
policy, request a review, read a credential value, or prove that external
repository policy is currently configured. External policy acceptance remains
separate pending work.

## Dispatch binding

The routing entry expects a GitHub `repository_dispatch` event whose action is
exactly `desktop-release` and whose `client_payload` contains exactly one key,
`tag`, with a strict semantic-version value. The event repository id and name,
and the event sender, are bound to the canonical repository API response. The
sender must be the personal repository owner; event-supplied routing fields are
never accepted as overrides.

Current-run facts come only from the trusted caller/environment: run id, run
attempt, server SHA, and workflow SHA. The canonical run API object must match
all of them exactly, must be a `repository_dispatch` run, must be `in_progress`
with a null conclusion, must have `main` as its head branch, and must have the
same repository and head-repository identities as the canonical repository.
The run actor and triggering actor must both be the personal owner and the same
positive user id as the event sender. The workflow path must be exactly
`.github/workflows/desktop-release.yml`, optionally suffixed by `@main` or
`@refs/heads/main`; arbitrary tag or ref suffixes are refused.

## Policy reuse and ancestry

The routing path reuses every C1 policy gate: app-bound required status checks,
review enforcement with the auxiliary no-bypass ruleset proof, admin/force/
delete settings, immutable tag rules, production environment branch restriction,
and environment-only production credential metadata. It resolves the exact real
local tag object and commit, requires that commit to be an ancestor of the
trusted workflow SHA, and requires the workflow SHA to be an ancestor of the
current API-protected default-branch tip.

## Outputs and diagnostics

Only an authorized decision emits `tag`, `commit`, `version`, and `prerelease`
to `GITHUB_OUTPUT`. Refusals emit no outputs. Diagnostic output contains only
the fixed decision and refusal enum; event values, actor values, credential
names, and raw transport errors are not printed.

A successful local check is source-level evidence only. It is not an actual
external policy acceptance, an independent security review, or proof that a
real repository has the required settings.

## C2b workflow and cutover prerequisites

The active workflow is `.github/workflows/desktop-release.yml`. The `authorize`
job checks out `github.workflow_sha` with full history and tags, uses only
`contents: read` and `actions: read`, and runs this routing entry before any
candidate code, write token, or production secret is used. Draft, Windows, and
macOS jobs depend on authorization and successful predecessor jobs. The final
verifier checks out `github.workflow_sha` and runs the trusted verifier/helper/
config, not scripts from the candidate commit.

Before any real release tag is dispatched, the owner must verify externally
that production credentials are isolated to the `production` environment,
`main` protection and required immutable-tag/review gates are enforced, and
every legacy tag-triggered workflow or script in historical tag trees is
disabled or made inert. Committing the new workflow cannot retroactively stop
workflows embedded in old tags.

### External read-metadata credential

The `authorize` job runs in the separate `release-metadata` environment and
uses only the owner-supplied `RELEASE_METADATA_READ_TOKEN` environment secret
for metadata API calls. It never falls back to the builtin `github.token` for
those reads and never receives production signing keys. The checkout step
continues to use the builtin read-only token with persisted credentials
disabled.

The owner must create and protect `release-metadata` with an exact `main`-only
deployment branch policy **before** storing the token or dispatching the
workflow. A GitHub environment reference can otherwise auto-create an empty
environment. Source checks run after the token exists and cannot prove that
bootstrap delivery was safe.

Fill the blank environment secret outside this task with a repository-scoped
fine-grained token whose read scopes cover Administration, Secrets,
Environments, Actions, Metadata, and Contents. `Contents: read` is required
because the same metadata token performs the `GET /repos/{repo}/branches/main`
branch metadata read; the separate builtin checkout token only fetches Git
objects and does not supply GH CLI/API scopes. No write grant is recommended.

Ruleset `bypass_actors` visibility depends on the repository user/write role
versus the token's read scopes; the primary GitHub documentation does not
guarantee that an owner's read-only token can see every bypass actor. Do not
assume invisibility means empty. The explicit bypass proof is still mandatory:
absent or redacted metadata refuses. Live positive policy and read-only scope
verification remain external acceptance work. Existing real repository policy
and secret facts remain private; this source checkpoint makes no claim that any
repository is configured safely.

## Future CI hook

This checkpoint does not add a CI job or edit the monolithic `check.yml`. When
the separate shared-CI alignment is ready, the exact cheap workflow contract
command to add is:

```sh
python3 -m unittest scripts/test_desktop_release_workflow.py
```

### Local workflow-contract tests

The workflow contracts use the test-only PyYAML dependency pinned in
`scripts/requirements-test.txt`; it is not a runtime/product dependency. Use an
isolated virtual environment outside the checkout and do not install into the
global interpreter:

```sh
python3 -m venv /tmp/locklark-release-workflow-venv
/tmp/locklark-release-workflow-venv/bin/pip install \
  -r scripts/requirements-test.txt
/tmp/locklark-release-workflow-venv/bin/python -m unittest \
  scripts/test_desktop_release_workflow.py
```
