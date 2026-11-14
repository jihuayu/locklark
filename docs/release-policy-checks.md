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
  last-push approval, and has empty `bypass_pull_request_allowances.users`,
  `.teams`, and `.apps` lists. Missing, malformed, or unknown review or bypass
  metadata is refused.
- `enforce_admins` is enabled, while force pushes and deletions are disabled.

These are necessary source/metadata policy checks, not completed external
policy acceptance. The presence of this code does not apply any setting,
request a review, read a secret value, or grant permissions. Existing
repository policies remain unaccepted unless the read-only metadata proves
them, and a successful local test is not production security proof.

The routing and external-policy preconditions are documented separately in
[release-trust.md](release-trust.md). Tests for this contract live in
`scripts/test_authorize_desktop_release.py`; run only the focused tests, not
release builds or archive acceptance suites.
