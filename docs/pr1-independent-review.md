# PR #1 independent code review

Review baseline: `f0c58e374a7f4dd6d4e8ea98ec880dbc72594929` on `codex/first-preview`; main `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`.

The user explicitly authorized independent sub-agents using `gpt-6-luna` with `max` reasoning effort, and authorized continued fixes, tests, pushes, and squash merges once gates are satisfied without repeated confirmation. These code reviews are not GitHub human approvals or external cryptographic certification.

Review assignments: personal vault/backup/restore/audit; MCP gateway/authorization/execution/receipt/audit; references/projections/binding/TOTP/password/1PUX/ConPTY.

Baseline CI: https://github.com/jihuayu/locklark/actions/runs/41944072696 — Ubuntu and Windows succeeded. Main branch protection details returned HTTP 403 to this integration; normal PR merge must respect server enforcement without admin/bypass options.

## Personal vault and recovery

Independent reviewer: Luna/max, task `luna_recovery`. No reproducible merge-blocking defect found in this scope. Reviewed CLI restore ordering, old factors, LLR2 archive digest and signed history, legacy rejection, capacity errors, target preflight, atomic non-overwrite publication, and personal audit validation.

Executed targeted personal recovery/security/lifecycle tests (`go test -count=1 -timeout=10m ./internal/personal -run 'TestIndependentRecovery|TestRecoveryRejectsResignedHistory|TestRecoveryLimitsAreNotCredentialErrors|TestRestoreRejectsDirectoryBeforeCreatingDestination|TestPreparedRecoveryPinsPayloadAndRefusesLateTarget|TestLegacyAndIncompleteRecoveryFailExplicitly|TestBackupPlaintextAndHistoryLimits|TestRestoreRejectsIdleFIFO|TestRestoreAcceptsRegularFileThroughSymlink|TestPublishDoesNotClobberConcurrentCreator|TestAuditAndSnapshotTampering|TestPersonalVaultLifecycle|TestReadOnlyOperationLeavesVaultCiphertextUnchanged'`), CLI build, and `python3 scripts/personal_acceptance.py /tmp/locklark-review/locklark`: passed. Extra PTY checks for incorrect original password and Secret Key rejected before issuing a new key or creating the destination.

The reviewer reproduced acceptance of an internally consistent older whole-vault bbolt file: personal audit has no independent freshness witness yet. This documented limitation remains open and is different from offline LLR2 archive-origin pinning. Windows native special-file/path-swap behavior also remains unverified; existing non-Unix Stat/Open/fstat does not establish Unix-style nonblocking guarantees.

## Reference, generation, inventory, and terminal foundations

Independent reviewer: Luna/max, task `luna_foundations`. No confirmed blocking defect found. Reviewed reference parsing/resolution/CheckTarget, personal and fixture metadata projection/binding, TOTP and password cores, bounded 1PUX archive/JSON/file/section inventory, and the ConPTY harness against their documented restricted scope. Metadata binding is not authorization; inventory success is not lossless migration.

Executed `/tmp/locklark-tools/go/bin/go test -count=1 ./internal/reference ./internal/personal ./internal/totp ./internal/password ./internal/onepux ./internal/preview -run 'Test(Parse|Resolve|CheckTarget|Bind|ProjectReference|Projection|FixtureReference|TOTPAuthenticated|RFC|ParseCanonical|ParseRejects|Sensitive|ConfigurationConcurrent|DefaultPolicy|ExactEntropy|RejectionSampling|RandomFailures|SecretRedacts|ConcurrentSystem|GeneratedPassword|Inventory|Directory|FileReferences|SectionInventory|Onepux)'`: passed. `python3 -m unittest discover -s scripts -p test_personal_windows.py`: 3 passed.

Fixed-version op comparisons, broad real 1Password exports, external cryptographic assessment, and production disclosure/transactional authorization are not validated by this review. The reviewer ran only synthetic ConPTY locally; native Windows evidence is the separate CI run above.

## Gateway review

Independent reviewer: Luna/max, task `luna_gateway`. No confirmed reproducible blocking defect found. Reviewed `internal/agentmcp/{server,paths}.go`, `internal/gateway/{intent,pulls,upstream}.go`, `plugins/github-pull-reader/{index.ts,runner.go}`, `cmd/locklark/{bridge,invoke,pull,session}.go`, and preview session/inbox/decision/invoke/audit/status/courier/outbox/profile/result paths. Covered signed session and fixed target binding, revocation, single-use intent before unlock, crash-unknown handling, replay rejection, scoped result collection, and Bun proposal boundaries.

Executed (Go binary `/tmp/locklark-tools/go/bin/go`, Bun `/tmp/locklark-tools/bun-linux-x64/bun`):

- Initial `LOCKLARK_TEST_BUN=... go test -race ./internal/agentmcp ./internal/gateway ./internal/preview ./plugins/github-pull-reader ./cmd/locklark` was stopped after about five minutes. agentmcp/gateway had passed; full preview race did not finish and is NOT counted as passing.
- `go test -race ./internal/preview -run 'Test(BridgeCollectRequiresOriginalRecipient|RetiredModuleProfileStillPermitsReceiptRecovery|OutboxCoalescesConcurrentCallsAndRestoresLostPublication|StatusChallengeIsReadOnlyAndBindsCurrentSession|RedemptionRunsOnlyOnce|IntentIsDurableBeforeFieldUnlock|AbandonedClaimCannotRunAgain)$'`: passed, 199.924s.
- `LOCKLARK_TEST_BUN=... go test -race ./internal/agentmcp ./internal/gateway ./plugins/github-pull-reader ./cmd/locklark`: passed (cached).
- CLI build and `PATH=/tmp/locklark-tools/bun-linux-x64:$PATH python3 scripts/mcp_acceptance.py /tmp/locklark-gateway-audit`: passed.

Live upstream delegation, third-party Bun OS sandboxing, signed installation, and independent freshness witnesses for whole decision-database rollback remain unimplemented acceptance items. Recorded-response demonstrations do not validate those capabilities.

## Disposition

All three assigned reviews completed without confirmed merge-blocking findings for the current explicitly scoped preview. There are no newly confirmed defects requiring a fix/re-review cycle in these reports. The aggregate review closes the recorded independent code-review backlog for the reviewed recovery, MCP and foundation scopes, including the previously outstanding MCP changes; it does not close the product/platform gaps listed above or constitute external cryptographic certification.

This documentation-only handoff follows the reviewed code baseline; no production code changes were made during review. Require checks on its actual new head before ordinary PR squash merge. Preserve all historical validation records as evidence of their original scope and status; this document supersedes their pending code-review status only for the scopes explicitly listed here.


