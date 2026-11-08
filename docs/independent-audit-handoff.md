# Independent security audit handoff

Scope date: 2026-11-08 (Hong Kong). This document prepares an independent review;
it does not claim an auditor has been engaged or has attested to this product.
Issue #54 remains open until the reviewer verifies the final remediation.

## Freeze and evidence

The reviewer must record the full reviewed commit and reproducible build hashes.
PR #61 was merged as `4205231`; it removed the browser timer that could erase a
later clipboard owner. PR #62 is an evolving draft, so its earlier green jobs
cannot establish the final source state. Use the final PR check receipts.

Use only synthetic vaults, credentials and RP fixtures for reproduction. Keep
raw test directories, worker transcripts, private runtime configuration, memory
dumps, clipboard contents and signing keys outside the packet. Attach bounded
public test summaries, source references, fixed error categories and artifact
hashes. A screenshot of approval is not evidence of cryptographic correctness.

## Boundaries to review

| Boundary | Source / required question |
| --- | --- |
| Page to isolated extension | `browser-extension/webauthn.js`, `content.js`: source, document, frame, challenge and navigation binding; no page-created approval |
| Extension to background | `background.js`: browser-observed sender identity, capability, active-document and cancellation checks; no secret-bearing storage |
| Background to native | `internal/browserhost`: strict bounded protocol, peer/registration identity, stale and replayed messages, queued writer authority |
| Vault transaction | `internal/personal`, `internal/vault`: full authentication, exact revisions, single commit gate, atomic snapshot/audit, error cleanup and cold replay |
| Passkey | `internal/passkey`, native approval: independent RP/signature validation, truthful UP/UV, exact credential selection and removal, global revocation of queued results |
| OS verification | `internal/osverify`: protected capsule release and per-operation verification; genuine Hello/Touch ID evidence required |
| CLI disclosure | `internal/cliprofile`, `internal/personal/run_bundle.go`, broker: explicit targets/program/args/profile binding, private temporary files, stdio, no refusal-to-factor fallback |
| Clipboard | `internal/nativeclipboard`, desktop/popup adapters: owned cleanup, earliest deadline, cancel-before-write, partial/unknown outcomes and foreign-owner preservation |
| Safari | `safari`: signed peer/team/profile binding, fixed helper/argv/env, no SIGPIPE termination, bounded lifecycle and actual Xcode/Safari acceptance |
| Recovery and import | backup, restore, KDBX/1PUX and transfer: malformed/oversized inputs, downgrade refusal, all-or-nothing conflicts and secret lifetime |

## Reproduction commands

Use the repository-supported Go version and regular user privileges. Review the
commands before running a broad native GUI suite; one headed GUI suite owns the
desktop at a time. Product approval must use ordinary UI input.

```sh
go test ./internal/vault ./internal/passkey ./internal/personal
go test -race ./internal/nativeclipboard ./internal/browserhost
node --test browser-extension/test/*.test.js
python3 -m unittest discover -s scripts -p 'test_native_acceptance*.py'
python3 scripts/test_safari_package.py
# macOS only; also runs the independent default-SIGPIPE process probe:
safari/scripts/test_safari_swift.sh
```

Real browser journeys must independently verify RP ID, origin, challenge,
credential ID, account, flags and signature with the RP verifier. Exercise lock,
cancel, navigation, removal, session expiry, disconnect, restart and a blocked
writer before releasing queued output. For same-login multiple credentials,
verify sibling preservation and cold replay after grouped signal mutations.

## Findings and closure

Each finding records the reviewed commit, source location, affected authority,
synthetic reproduction, observed result, expected result, severity rationale,
fix commit and final verification. Separate confirmed defects from hypotheses
and unavailable platform evidence. Do not close a security finding solely from
an LLM's explanation or from an implementation-mirroring test.

External requirements are tracked in #50 (fresh hardware verification), #51
(real Windows/macOS workflows), #53 (store/signing/install/update), #55 (signed
Safari runtime), and #57 (authorized reference and real accessibility). Source
review and Linux mocks do not substitute for these acceptance conditions.
