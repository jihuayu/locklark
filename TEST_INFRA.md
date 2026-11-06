# Locklark M5 Opaque-Box E2E Test Infrastructure

This document defines the architecture, runtime contract, and operating
instructions for the repository-wide opaque-box end-to-end (E2E) suite. The
suite verifies the user-facing product, not internal Go functions: every test
starts real binaries, speaks the real native-messaging wire protocol, builds
the real browser extension, or drives the real desktop process under Xvfb.

The infrastructure in this change consists of:

| Path | Purpose |
| :--- | :--- |
| `tests/e2e/harness.py` | Registration decorator, result types, native framing, isolated `E2EContext`, PTY runner, binary builder, canary checks, progressive feature gate. |
| `tests/e2e/__init__.py` | Public re-exports for test modules. |
| `scripts/e2e_runner.py` | Discovery, filtering, execution, JSON report, self-test, and exit-code policy. |
| `TEST_INFRA.md` | This document. |

The tier modules themselves are added incrementally on `feat/e2e-suite`. The
runner deliberately tolerates a missing canonical module so the infrastructure
can be reviewed and used before the test corpus is complete; a module that
exists but fails to import is always reported as a hard error.

## 1. Four-Tier Opaque-Box Architecture (F1–F17)

### 1.1 Feature inventory and milestone mapping

F1–F17 are the product features from `PROJECT.md` that the M5 suite must cover.
F18 is the E2E test track itself; F19 is the final M6 hardening gate.

| Feature | Opaque-box obligation | Milestone |
| :--- | :--- | :--- |
| **F1** | PR #40 rebase on `main`: SSH-key and Passkey coexistence in the same vault/journal, Firefox auto-submit fix. | M1a |
| **F2** | Inline autofill menu, configurable auto-login (`autoSubmit`), native ES256 Passkeys, browser fallback option. | M1a |
| **F3** | PR #37: authenticated team synchronization and mobile vault core, including Passkey exclusion/preservation. | M1b |
| **F4** | PR #42: protected team identities, dual-key admission, and first-device sync bootstrap. | M1b |
| **F5** | Desktop timer/state correctness: clipboard and idle timers independent of redraw, cancel edits on lock, preserve filter on refresh (`#32`, `#33`, `#34`). | M2 |
| **F6** | Item model v2: categories, sections, typed custom fields, multiple URLs, tags, favorites, password history, and 1PUX import mapping. | M2 |
| **F7** | Shared desktop↔extension session over authenticated local IPC: one unlock, lock propagation, no re-pairing. | M2 |
| **F8** | Desktop UI v2: sidebar, multiple vaults, full editor, generator, configurable auto-lock, full-text search, item history, Recently Deleted retention/purge, attachments. | M2 |
| **F9** | Offer to save/update after a successful submit, plus the inline password generator. | M3 |
| **F10** | Popup vault: search, browse, view/edit, Open & Fill, keyboard shortcuts, context menu, options page. | M3 |
| **F11** | Identity and credit-card fill, continuous multi-step logins, split OTP fields, same-site iframes. | M3 |
| **F12** | Browser parity checklist and REA obligation/coverage ledger verification. | M3 |
| **F13** | Watchtower checks: weak, reused, unsecured HTTP, and opt-in k-anonymity HIBP breach lookup. | M3 |
| **F14** | `internal/cliprofile` registry: `gh`, `aws`, `kubectl`, `docker`, `npm`, `terraform`, `git`, `psql`, and `token`. | M4 |
| **F15** | `personal.RunBundle`: multi-secret `item.run.bundle` intent, `0600` files in the run root, and cryptographic spec-digest binding. | M4 |
| **F16** | `internal/clibinding` and `locklark cli init|run|list|show|remove|shell-init`, including shell functions, `--help` bypass, and recursion guard. | M4 |
| **F17** | Desktop broker for CLI runs: unlock once over local IPC with native approval and terminal-scoped leases. | M4 |

### 1.2 The four tiers

The suite is requirement-driven and has four independent layers. Counts are
minimums, not aspirational totals: every feature must be exercised on its own
and in combination.

| Tier | Name | Requirement | Minimum |
| :--- | :--- | :--- | ---: |
| **Tier 1** | Feature Verification | Happy-path and core functional obligations for every feature F1–F17, through user-facing entry points. At least five tests per feature. | **85** |
| **Tier 2** | Boundary, Negative & Security | Invalid inputs, tampered frames, origin/permission mismatches, timeouts and cleanup, untrusted paths, locked-state refusal, rollback, and canary non-leakage. At least five tests per feature. | **85** |
| **Tier 3** | Cross-Feature Pairwise | Interactions between two features (for example Item Model v2 × Browser Fill, Shared IPC × Passkey/Autofill, Desktop Lock × CLI Broker). | **17** |
| **Tier 4** | Real-World End-to-End Scenarios | Multi-step user journeys spanning vault creation, import, desktop editing, browser signup/save/fill/OTP/Passkey, CLI injection, and audit/health checks. | **9** |
| | | **Total suite minimum** | **196** |

A test may reference more than one feature in Tier 3 and Tier 4. The runner
counts it under every referenced feature; the overall total counts the test
once.

### 1.3 Test module layout

| Path | Contents |
| :--- | :--- |
| `tests/e2e/harness.py` | Shared harness (no test cases). |
| `tests/e2e/__init__.py` | Public harness re-exports. |
| `tests/e2e/tier1_f01_f08.py` | Tier 1 coverage for F1–F8. |
| `tests/e2e/tier2_f01_f08.py` | Tier 2 boundary/security coverage for F1–F8. |
| `tests/e2e/tier1_f09_f17.py` | Tier 1 coverage for F9–F17. |
| `tests/e2e/tier2_f09_f17.py` | Tier 2 boundary/security coverage for F9–F17. |
| `tests/e2e/tier3_pairwise.py` | Cross-feature pairwise cases. |
| `tests/e2e/tier4_scenarios.py` | Multi-step real-world scenarios. |

Test IDs follow `T<tier>_F<feature>_<nn>` for feature-focused cases and
`T3_<nn>` / `T4_<nn>` for pairwise/scenario cases. Registration is explicit:

```python
from tests.e2e.harness import e2e_test

@e2e_test("T1_F1_01", 1, "F1", "SSH and Passkey items coexist in one vault")
def test_mixed_vault(ctx):
    ...
```

`register_test` validates the test ID, tier (1–4), and every feature name
(`F1`–`F17`). Duplicate IDs with a different function raise
`ValueError("Duplicate test_id: ...")` immediately at import time, so a broken
registration cannot silently disappear from the report.

## 2. The Four User-Facing Entry Points

### 2.1 Entry point 1: `locklark` CLI

- Binaries: `cmd/locklark` (`locklark`) and, when the branch provides it,
  `cmd/locklark-team-sync` (`locklark-team-sync`).
- Interactive commands (`personal init`, `add-login`, `list`, `reveal-login`,
  `otp`, `search`, `health`, import/export, `run-cli`, and the M4 CLI wrappers)
  are driven through a **real POSIX PTY**:
  - `pty.openpty()` creates a master/slave pair.
  - The child calls `os.setsid()`; when `/dev/tty` must be usable (for example
    `personal run-cli` and `cli run`), the harness also issues
    `fcntl.ioctl(slave, termios.TIOCSCTTY, 0)`.
  - The CLI's hidden prompts are written to stderr, so the slave is attached to
    stdin and stderr while stdout remains a normal pipe carrying the JSON
    receipt.
  - Prompt answers are written to the PTY master. The harness checks that
    `termios.ECHO` is disabled while a secret is being entered and that echo is
    restored after the process exits.
  - Issued `LL1-…` Secret Keys and `LLR2-…`/`LLR1-…` recovery kits are parsed
    from the terminal transcript by `ISSUED_TOKEN_RE`; a prompt with
    `answer=None` re-uses the issued value, exercising the real confirmation
    prompt instead of assuming it.
- Non-interactive commands use ordinary pipes via `ctx.run_cli(...)`. This
  still starts the compiled binary; it does not call Go internals.
- All commands run with `TMPDIR` pointing at the per-test `0700` directory and
  `cwd` defaulting to that directory.

### 2.2 Entry point 2: browser native-messaging hosts

- Binaries: `locklark-browser-chromium`, `locklark-browser-firefox`, and
  `locklark-browser-register`.
- Protocol: `internal/browserhost/protocol.go` uses a 4-byte **native-endian**
  unsigned length (`struct.pack("=I", ...)`) followed by UTF-8 JSON, with a
  256 KiB input/output bound. The harness implements both directions:
  `encode_native_frame(...)` and `read_native_frame(...)`.
- Launch validation is part of the test surface:
  - Chromium accepts the canonical origin
    `chrome-extension://geldnhjapnackobgknocomedmjgphnpe/` (and an optional
    Windows parent-window argument).
  - Firefox accepts an absolute canonical
    `org.locklark.browser.json` path plus `browser@locklark.local`.
- The native host is a native GUI process. On a headless VM the harness wraps
  it in `xvfb-run -a -s "-screen 0 1280x900x24"` when `DISPLAY` is absent and
  `xvfb-run` is installed. `probe_native_host_frame(...)` sends one or more
  frames over stdin, closes stdin, collects framed stdout, and records timeout
  and stderr evidence.
- `locklark-browser-register` is tested through its real CLI flags (`--browser`,
  `--host`, `--output`, `--replace`, `--register-user`) and the manifest
  artifact it creates.

### 2.3 Entry point 3: browser extension

- Build command: `node browser-extension/build.js chromium` and
  `node browser-extension/build.js firefox`, run from the repository root.
  `ctx.ensure_extension_built()` caches the result per runner process and
  asserts that both `browser-extension/dist/chromium` and
  `browser-extension/dist/firefox` contain `manifest.json`, `background.js`,
  and `popup.html`.
- Extension behavior is exercised with the existing Node DOM harness
  (`scripts/browser_extension_dom.cjs`, `scripts/browser_native_acceptance.mjs`,
  `scripts/browser_otp_acceptance.mjs`, and related scripts) through
  `ctx.run_node(...)`, and with Playwright when the suite's browser fixtures
  are available. The build output is ignored by git; tests never edit the
  source files under test.
- The extension is an opaque artifact: tests inspect the built manifest and
  observable page/DOM behavior, not private JavaScript internals.

### 2.4 Entry point 4: desktop application

- Binary: `locklark-desktop` (`cmd/locklark-desktop`).
- The desktop process is launched inside an isolated display and D-Bus session,
  typically:
  `dbus-run-session -- xvfb-run -a -s "-screen 0 1280x900x24" ./locklark-desktop`.
- UI interaction is performed through AT-SPI accessibility and XTest input
  helpers (for example `scripts/browser_native_x11.py`,
  `scripts/desktop_native_acceptance.py`, and `scripts/ssh_native_x11.py`).
- Vault evidence is additionally checked from the outside: a read-only copy of
  the bbolt database can be opened with `go.etcd.io/bbolt` to verify that the
  expected buckets/keys exist without trusting the UI's own report. Tests never
  mutate the live database behind the application's back.
- Desktop tests are permitted to skip *only* by reporting a real missing
  platform prerequisite as `PENDING_FEATURE` when the feature itself is not
  merged; they must not report PASS when the process never started.

## 3. VM Environment and Security Setup

All Go builds and tests in this VM use the private temporary recipe:

```sh
umask 077
mkdir -p -m 0700 "$HOME/.cache/lltmp"
export TMPDIR="$HOME/.cache/lltmp"
export GOPROXY=direct
```

`ensure_vm_temp_root()` performs the equivalent at runner startup:
`os.umask(0o077)`, creates `$HOME/.cache/lltmp` with mode `0700`, exports
`TMPDIR`, and sets `GOPROXY=direct` only if the caller has not set it.
`ensure_binaries_built()` builds into `$HOME/.cache/lltmp/e2e-bin` (`0700`) and
passes the same `TMPDIR`/`GOPROXY` to `go build`.

Why these settings matter:

- `umask 077` prevents vaults, sockets, and temporary credential files from
  being created world-readable.
- The runner never uses `/tmp` for a test's private state. `/tmp` is a shared
  namespace and is not a valid private parent for this product's trust checks.
- `GOPROXY=direct` is required because the configured module proxy returns 403
  for some modules in this VM; the Go build must not depend on a mirror.

### 3.1 Container user-namespace caveat and `localpath.TrustedTemporaryParent`

The VM runs in a user namespace with an unusual ownership map:

| Path | Owner in this VM | Typical GitHub Actions owner |
| :--- | :--- | :--- |
| `/` | `uid 1000` (the container user), mode `0555` | `root`, mode `0755` |
| `/home` | `nobody` / `uid 65534`, mode `0755` | `runner` / `root`, non-writable |
| `/tmp` | `nobody` / `uid 65534`, mode `1777` | `root`, mode `1777` (sticky) |
| `$HOME/.cache/lltmp` | current user, mode `0700` | current user, mode `0700` |

`localpath.TrustedTemporaryParent` does not merely stat the leaf. It resolves
symlinks once, then walks **every canonical ancestor** and rejects an ancestor
that is not owned by root or the effective user, or that is group/other
writable without being a root-owned sticky directory. The final directory must
be owned by the effective user with no group/other permission bits, unless it
is a root-owned sticky directory.

Consequences in this VM:

- `/` is owned by the current `uid 1000` and is non-writable, so it passes the
  ancestor check.
- `/home` and `/tmp` are owned by `nobody` (`uid 65534`), which is neither
  root nor the effective user. Any path beneath them is rejected even if the
  leaf is a private `0700` directory. A private `TMPDIR` under
  `$HOME/.cache/lltmp` still traverses `/home` and can therefore be rejected by
  the product's own trust check.
- Tests that exercise `personal run-cli`, `run-env`, `inject-json`, or other
  trusted-run-root paths must not "fix" this by loosening `localpath`. They
  observe the real refusal and record it as an environment limitation, or rely
  on the GitHub Actions runner where `/`, `/home`, and `/tmp` have the
  expected ownership. This is why some product-level trusted-temp tests are
  CI-authoritative.
- The harness itself keeps all test state in `$HOME/.cache/lltmp/e2e-runs`
  with `umask 077`; this gives process isolation and prevents accidental
  disclosure even where the product's stricter ancestor policy refuses to use
  the same path for credential execution.

## 4. Running `scripts/e2e_runner.py`

All commands are run from the repository root
(`/home/antigravity/jihuayu/worktrees/m5-e2e`).

| Command | Behavior |
| :--- | :--- |
| `python3 scripts/e2e_runner.py --help` | Show all options without importing test modules or building binaries. |
| `python3 scripts/e2e_runner.py --list` | Print `TEST_ID`, `TIER`, `FEATURES`, `SUMMARY` for matching tests, plus Tier 1–4 and F1–F17 registration counts. Exits 0 without building. |
| `python3 scripts/e2e_runner.py --tier 1` | Run only Tier 1. |
| `python3 scripts/e2e_runner.py --tier 4` | Run only the real-world scenarios. |
| `python3 scripts/e2e_runner.py --feature F1` | Run every test tagged F1. |
| `python3 scripts/e2e_runner.py --feature F1,F2` | Run tests intersecting either feature. |
| `python3 scripts/e2e_runner.py --feature F1 --feature F9` | Same, using repeated flags. |
| `python3 scripts/e2e_runner.py --feature all` | Explicitly disable feature filtering. |
| `python3 scripts/e2e_runner.py --id T1_F3` | Run tests whose ID contains `T1_F3`. |
| `python3 scripts/e2e_runner.py --json-out out/e2e-report.json` | Write the structured JSON report. |
| `python3 scripts/e2e_runner.py --strict` | Release-gate mode: exit 1 on any `FAIL` **or** `PENDING_FEATURE`. |
| `python3 scripts/e2e_runner.py --skip-build` | Reuse `$HOME/.cache/lltmp/e2e-bin` when every required binary is present and executable. |
| `python3 scripts/e2e_runner.py --self-test` | Verify the harness against the real compiled binaries and built extension. |
| `python3 scripts/e2e_runner.py --workers 4` | Accepted for CLI compatibility; tests remain isolated and serial in this implementation. |

### 4.1 Execution and progress

Before running tests the runner builds `locklark`,
`locklark-browser-chromium`, `locklark-browser-firefox`,
`locklark-browser-register`, `locklark-desktop`, and (when
`cmd/locklark-team-sync` exists) `locklark-team-sync`. Each test then gets a
fresh `E2EContext` with a random per-test directory under
`$HOME/.cache/lltmp/e2e-runs/<safe-id>-<rand8>` (mode `0700`), which is always
removed in `finally`.

Each result is printed as it finishes:

```text
[PASS] T1_F1_01 (Tier 1, F1) [183ms]
[PENDING_FEATURE] T1_F9_01 (Tier 1, F9) [12ms]
[FAIL] T2_F11_03 (Tier 2, F11) [401ms]
```

A final summary shows totals, per-tier counts, and per-feature counts. A
`--json-out` report has this shape:

```json
{
  "summary": {
    "total": 0,
    "pass": 0,
    "pending_feature": 0,
    "fail": 0,
    "strict": false,
    "duration_sec": 0.0
  },
  "by_tier": {
    "1": {"total": 0, "pass": 0, "pending_feature": 0, "fail": 0},
    "2": {"total": 0, "pass": 0, "pending_feature": 0, "fail": 0},
    "3": {"total": 0, "pass": 0, "pending_feature": 0, "fail": 0},
    "4": {"total": 0, "pass": 0, "pending_feature": 0, "fail": 0}
  },
  "by_feature": {
    "F1": {"total": 0, "pass": 0, "pending_feature": 0, "fail": 0}
  },
  "results": [
    {
      "test_id": "T1_F1_01",
      "tier": 1,
      "features": ["F1"],
      "summary": "...",
      "status": "PASS|PENDING_FEATURE|FAIL",
      "duration_sec": 0.123,
      "message": ""
    }
  ]
}
```

`by_feature` always contains all of `F1`–`F17`; `by_tier` always contains
`1`–`4`.

### 4.2 Exit codes

| Condition | Exit |
| :--- | ---: |
| Any `FAIL` | `1` |
| `--strict` and any `PENDING_FEATURE` | `1` |
| No failures, non-strict, even with pending features | `0` |
| No tests matched and no failures | `0` |
| `--list`, `--help`, successful `--self-test` | `0` |

### 4.3 Built-in self-test

`--self-test` is not a mock. It builds the real binaries and then verifies:

- `ensure_vm_temp_root`, binary executability, and isolated context paths.
- `run_cli` against the compiled CLI.
- `run_node` with the isolated `TMPDIR`.
- `init_vault` through real PTY prompts, including issued Secret Key parsing,
  vault permissions, and absence of plaintext factors in the vault file.
- `add_login` and the subsequent `personal list` revision lookup.
- `run_pty_cli` hidden prompts, no echo during secrets, and echo restoration.
- Native framing round-trips and a live `probe_native_host_frame` against
  `locklark-browser-chromium` under Xvfb.
- `ensure_extension_built` for both Chromium and Firefox, including manifest
  checks.
- `assert_no_canary_leak` positive/negative cases and idempotent cleanup.
- `require_feature` raising exactly
  `[PROGRESSIVE_UNIMPLEMENTED: F#] ...` when gated.

Run it after changing harness code:

```sh
python3 scripts/e2e_runner.py --self-test
```

## 5. Progressive Testability Policy (`PASS` vs `PENDING_FEATURE` vs `FAIL`)

M5 lands the harness while F1–F17 are still spread across M1a–M4 branches. The
suite must be runnable at every intermediate point without faking success or
silently hiding missing work. The three statuses are therefore strict:

### `PASS`

The test invoked the real user-facing entry point, observed the required
behavior, and every assertion held. No skip markers, hardcoded outputs, or
mock-only paths are allowed. A test that never started the product cannot PASS.

### `PENDING_FEATURE`

The test first performed a **real probe** of the current branch through one of
the four entry points and confirmed that the target feature is not yet merged.
Only then may it call:

```python
ctx.require_feature(
    "F9",
    condition=probe_observed_real_capability,
    detail="post-submit save prompt is absent from this build",
)
```

which raises:

```text
[PROGRESSIVE_UNIMPLEMENTED: F9] post-submit save prompt is absent from this build
```

Valid probes include:

- CLI: run the compiled binary and observe a missing subcommand/flag, an
  explicit "unknown command" error, or an exit status that proves the behavior
  is not present.
- Native messaging: send a framed request to the real host and observe
  `type: "error"` / `refused`, an unknown message type, or a missing field.
- Extension: build the real artifact with `node browser-extension/build.js` and
  inspect the emitted files/manifest, or run the Node/Playwright DOM harness.
- Desktop: launch the real process and observe that the relevant control,
  protocol operation, or artifact is absent.

`PENDING_FEATURE` is not available as a shortcut for an import error, a
skipped test, a missing fixture, or a behavior that should already work on
`main`. Those are `FAIL`.

### `FAIL`

Any `AssertionError`, unexpected exception, timeout, missing binary, malformed
frame, unexpected successful disclosure, crashed process, or canary leak is a
`FAIL`. This includes a feature that is present but behaves incorrectly, and a
test that could not establish its preconditions. The runner prints the
traceback to stderr and records the exception message in the JSON `message`
field.

### Baseline vs release gate

- Normal mode (no `--strict`) is the development baseline: pending in-flight
  features do not make CI red, but any real failure does.
- `--strict` is the M6 release gate: both `FAIL > 0` and
  `PENDING_FEATURE > 0` exit non-zero. When all M1a–M4 features have landed,
  the expected strict result is zero pending and zero failing tests.
- The report always records the statuses separately, so a green non-strict run
  can never be mistaken for a complete M6 pass.

### 5.1 Writing a well-gated test

```python
from tests.e2e.harness import e2e_test

@e2e_test("T1_F9_01", 1, ["F9"], "post-submit save prompt")
def test_post_submit_save(ctx):
    ext = ctx.ensure_extension_built()
    probe = ctx.run_node(
        "const fs=require('fs');"
        f"const src=fs.readFileSync({str(ext[0] / 'background.js')!r},'utf8');"
        "process.stdout.write(String(src.includes('save-new')));"
    )
    ctx.require_feature(
        "F9",
        probe.stdout.strip() == "true",
        "post-submit save protocol is absent from the built extension",
    )
    # Continue with a real native-messaging or DOM assertion only after the
    # probe proves the capability exists.
```

This pattern keeps the suite honest at every branch point: the gate itself is
evidence-producing, and a merged feature must satisfy the real behavioral
assertions that follow.
