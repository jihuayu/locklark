# Desktop release routing: source-only C2a checkpoint

This document describes a **source-only** default-branch routing checkpoint.
It is not wired into any workflow and it does not dispatch a release, apply a
policy, request a review, read a credential value, or prove that external
repository policy is currently configured. C2b wiring and external policy
acceptance are separate pending work.

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
