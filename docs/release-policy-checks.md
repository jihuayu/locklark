# Desktop release policy checks

This document describes a generic **source contract** enforced by the
read-only release authorizer. It is not a current-policy audit, an independent
security review, or a production security proof. It contains no findings about
any real repository's settings or credential locations.

The authorizer checks classic branch-protection metadata for `main` and
requires all of the following:

- `required_status_checks.checks` contains exactly one check whose context is
  exactly `ci-required` and whose `app_id` is the public GitHub Actions app id
  `15368`. Context-only metadata, a renamed or missing check, an any-app
  sentinel such as `-1`, a null/boolean/string app id, a different app id, or
  duplicate matching checks is refused.
- `required_pull_request_reviews` requires a positive non-boolean
  `required_approving_review_count`, enables stale-approval dismissal and
  last-push approval, and rejects malformed or unknown review metadata.
- When the classic protection response explicitly includes
  `bypass_pull_request_allowances`, its `users`, `.teams`, and `.apps` lists
  must be present and empty. A present non-empty or malformed value is
  refused, and a valid branch ruleset cannot rescue it.
- When the classic response omits `bypass_pull_request_allowances`, absence is
  **not** treated as an empty allowlist. The authorizer instead requires one
  single canonical repository-level branch ruleset that is active, targets
  `branch`, includes exactly `refs/heads/main` with no exclusions, has an
  explicitly empty `bypass_actors` list, and contains one `pull_request` rule
  with a non-boolean approval count at least as strict as the classic count,
  plus enabled stale-review dismissal and last-push approval. Parent-scoped
  rulesets, split proofs across multiple rulesets, and summaries claiming
  different targets or enforcement do not satisfy this proof.
- `enforce_admins` is enabled, while force pushes and deletions are disabled.

The ruleset proof has a visibility limitation. GitHub may omit or hide
`bypass_actors` when the caller lacks permission to write the ruleset. The
authorizer requires the field to be explicitly present and empty; it never
treats an invisible field as empty, infers a bypass policy, or widens
credentials to obtain write access. If the read-only caller cannot see enough
metadata to prove the condition, validation refuses.

These are necessary source/metadata policy checks, not completed external
policy acceptance. The presence of this code does not apply any setting,
request a review, read a secret value, or grant permissions. Existing
repository policies remain unaccepted unless the read-only metadata proves
them, and a successful local test is not production security proof.

The routing and external-policy preconditions are documented separately in
[release-trust.md](release-trust.md). Tests for this contract live in
`scripts/test_authorize_desktop_release.py`; run only the focused tests, not
release builds or archive acceptance suites.
