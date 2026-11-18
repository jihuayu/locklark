package vaultfileclient

import (
	"context"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
)

const (
	// MaxLocalGenesisBatchCandidates bounds the caller-supplied descriptor
	// slice before any disk I/O or KDF.
	MaxLocalGenesisBatchCandidates = 128
	// MaxLocalGenesisBatchTargets bounds the successful unique target set that
	// is handed to the single personal owned-child batch.
	MaxLocalGenesisBatchTargets = 64

	maxLocalGenesisBatchPath    = 4096
	maxLocalGenesisBatchVaultID = 128
)

// LocalGenesisBatchCandidate is one deep-frozen preflight request. ConfigPath,
// WorkspaceRoot, VaultID and JournalPath are copied before any disk read; a
// caller mutation after the call cannot change the batch. The expected journal
// is part of this locator, not a routing hint.
type LocalGenesisBatchCandidate struct {
	ConfigPath    string
	WorkspaceRoot string
	VaultID       string
	JournalPath   string
}

// LocalGenesisBatchResult is one original-index delivery slot. A nil Err means
// Wrapper and Baseline were delivered. Target-local failures leave Wrapper nil
// and carry the finite ErrLocalReview value. Exact duplicate candidates share
// one Wrapper pointer for every original index; they are not independently
// revivable wrappers for the same child token.
type LocalGenesisBatchResult struct {
	Index    int
	Wrapper  *LocalGenesisSession
	Baseline LocalGenesisBaseline
	Err      error
}

type localGenesisBatchLocator struct {
	configPath    string
	workspaceRoot string
	vaultID       string
	journalPath   string
}

type localGenesisBatchGroup struct {
	locator        localGenesisBatchLocator
	indices        []int
	manifest       Manifest
	digest         string
	companion      Companion
	revision       string
	successor      *localGenesisSuccessorLocator
	checkpoint     *vaultfile.PolicyCheckpoint
	targetPosition int
	err            error
}

// These test seams are nil in production. They carry no factor, key, identity,
// recovery kit, wrapper, token, parent or unwrap capability. The after-auth
// seam runs after the single personal batch returns and before the client
// locator re-read. The before-delivery seam is parameterless and triggers only
// the final cancellation boundary. The cleanup observer receives only bounded
// finite counts/status after each real wrapper Close has returned.
var (
	localGenesisBatchAfterAuthForTest      func()
	localGenesisBatchBeforeDeliveryForTest func()
	localGenesisBatchCleanupForTest        func(closedWrappers, summaryBuffers int, summariesCleared bool)
)

func validLocalGenesisBatchCandidate(candidate LocalGenesisBatchCandidate) bool {
	return candidate.ConfigPath != "" && len(candidate.ConfigPath) <= maxLocalGenesisBatchPath &&
		candidate.WorkspaceRoot != "" && len(candidate.WorkspaceRoot) <= maxLocalGenesisBatchPath &&
		candidate.VaultID != "" && len(candidate.VaultID) <= maxLocalGenesisBatchVaultID &&
		candidate.JournalPath != "" && len(candidate.JournalPath) <= maxLocalGenesisBatchPath
}

func cloneLocalGenesisBatchItems(items []personal.VaultFileBaselineItem) []personal.VaultFileBaselineItem {
	if len(items) == 0 {
		return nil
	}
	return append([]personal.VaultFileBaselineItem(nil), items...)
}

// OpenLocalGenesisSessionsForAccount performs one fresh account unlock and a
// bounded initial owned-child fanout. Descriptors are deep-copied, length
// checked, exact-locator deduplicated, and conflict checked before any manifest,
// companion, journal or KDF work. Exact duplicate locators share one wrapper and
// one child token across their original indices. Any two different locators
// sharing a config path or journal path are a conflict: both are target-local
// errors, never a silent alias/replacement. If more than 64 unique targets pass
// preflight, the first 64 in original group order are batched and later valid
// groups receive ErrLocalReview.
//
// The account parent is still returned when the target set is empty or every
// target fails preflight. A global error means the unpublished parent and every
// created child were closed and joined; no result handles are delivered.
// Target-local posterior failures close only that exact child. The returned
// wrappers retain only the parent, opaque token and frozen locator.
func OpenLocalGenesisSessionsForAccount(ctx context.Context, accountPath string, password, key []byte, idle time.Duration, candidates []LocalGenesisBatchCandidate) (*personal.Session, []LocalGenesisBatchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(candidates) > MaxLocalGenesisBatchCandidates || accountPath == "" ||
		len(accountPath) > maxLocalGenesisBatchPath {
		return nil, nil, ErrLocalReview
	}
	results := make([]LocalGenesisBatchResult, len(candidates))
	for index := range results {
		results[index].Index = index
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	groups := make([]*localGenesisBatchGroup, 0, len(candidates))
	byLocator := make(map[localGenesisBatchLocator]*localGenesisBatchGroup)
	for index, candidate := range candidates {
		if !validLocalGenesisBatchCandidate(candidate) {
			results[index].Err = ErrLocalReview
			continue
		}
		locator := localGenesisBatchLocator{
			configPath: candidate.ConfigPath, workspaceRoot: candidate.WorkspaceRoot,
			vaultID: candidate.VaultID, journalPath: candidate.JournalPath,
		}
		group := byLocator[locator]
		if group == nil {
			group = &localGenesisBatchGroup{locator: locator}
			byLocator[locator] = group
			groups = append(groups, group)
		}
		group.indices = append(group.indices, index)
	}

	// A child is identified by its journal path. Different descriptors for the
	// same config or journal are rejected as conflicts before authentication;
	// exact duplicates were collapsed above and remain one group.
	conflicts := make(map[*localGenesisBatchGroup]bool)
	byConfig := make(map[string][]*localGenesisBatchGroup)
	byJournal := make(map[string][]*localGenesisBatchGroup)
	for _, group := range groups {
		byConfig[group.locator.configPath] = append(byConfig[group.locator.configPath], group)
		byJournal[group.locator.journalPath] = append(byJournal[group.locator.journalPath], group)
	}
	for _, list := range byConfig {
		if len(list) > 1 {
			for _, group := range list {
				conflicts[group] = true
			}
		}
	}
	for _, list := range byJournal {
		if len(list) > 1 {
			for _, group := range list {
				conflicts[group] = true
			}
		}
	}

	for _, group := range groups {
		if conflicts[group] {
			group.err = ErrLocalReview
			continue
		}
		manifest, digest, companion, err := readLocalGenesisLocatorForAccount(
			accountPath, group.locator.configPath, group.locator.workspaceRoot,
			group.locator.vaultID, group.locator.journalPath)
		if err != nil {
			group.err = ErrLocalReview
			continue
		}
		verified, err := verifyLocalGenesisCompanion(manifest, companion)
		if err != nil {
			clearLocalGenesisCheckpoint(verified.checkpoint)
			group.err = ErrLocalReview
			continue
		}
		group.manifest = manifest
		group.digest = digest
		group.companion = cloneLocalGenesisCompanion(companion)
		group.revision = verified.revision
		group.successor = cloneLocalGenesisSuccessor(verified.successor)
		clearLocalGenesisSuccessor(verified.successor)
		group.checkpoint = verified.checkpoint
	}

	targets := make([]personal.OwnedVaultFileTarget, 0, len(groups))
	uniqueTargets := 0
	for _, group := range groups {
		if group.err != nil {
			for _, index := range group.indices {
				results[index].Err = group.err
			}
			continue
		}
		if uniqueTargets >= MaxLocalGenesisBatchTargets {
			clearLocalGenesisCheckpoint(group.checkpoint)
			group.err = ErrLocalReview
			for _, index := range group.indices {
				results[index].Err = group.err
			}
			continue
		}
		uniqueTargets++
		group.targetPosition = len(targets)
		target := personal.OwnedVaultFileTarget{
			JournalPath: group.locator.journalPath,
			Checkpoint:  *group.checkpoint,
		}
		if group.successor != nil {
			target.Successor = &personal.OwnedVaultFileFirstSuccessorTarget{
				BackendRoot: group.successor.backendRoot,
				BackendName: group.successor.backendName,
				Pin:         cloneLocalGenesisGenesisPin(group.successor.pin),
			}
		}
		targets = append(targets, target)
	}
	defer func() {
		for _, group := range groups {
			clearLocalGenesisCheckpoint(group.checkpoint)
			clearLocalGenesisSuccessor(group.successor)
		}
	}()

	parent, childResults, err := personal.UnlockSessionWithOwnedVaultFileChildren(
		ctx, accountPath, password, key, idle, targets)
	if err != nil {
		return nil, nil, err
	}
	if parent == nil {
		return nil, nil, ErrLocalReview
	}
	if len(childResults) != len(targets) {
		for index := range childResults {
			if childResults[index].Token != (personal.VaultFileChildToken{}) {
				_ = parent.LockVaultFileChild(childResults[index].Token)
			}
			clearLocalGenesisItems(childResults[index].Items)
		}
		parent.Lock()
		return nil, nil, ErrLocalReview
	}
	for index := range childResults {
		if childResults[index].Index != index {
			for position := range childResults {
				if childResults[position].Token != (personal.VaultFileChildToken{}) {
					_ = parent.LockVaultFileChild(childResults[position].Token)
				}
				clearLocalGenesisItems(childResults[position].Items)
			}
			parent.Lock()
			return nil, nil, ErrLocalReview
		}
	}
	if localGenesisBatchAfterAuthForTest != nil {
		localGenesisBatchAfterAuthForTest()
	}
	if err := ctx.Err(); err != nil {
		for position := range childResults {
			if childResults[position].Token != (personal.VaultFileChildToken{}) {
				_ = parent.LockVaultFileChild(childResults[position].Token)
			}
			clearLocalGenesisItems(childResults[position].Items)
		}
		parent.Lock()
		return nil, nil, err
	}

	wrappers := make([]*LocalGenesisSession, 0, len(targets))
	consumed := make([]bool, len(childResults))
	wrappedTokens := make(map[personal.VaultFileChildToken]*LocalGenesisSession)
	cleanup := func(err error) (*personal.Session, []LocalGenesisBatchResult, error) {
		summaryBuffers := 0
		for index := range results {
			if results[index].Baseline.VaultID != "" || len(results[index].Baseline.Items) != 0 {
				summaryBuffers++
			}
		}
		closedWrappers := 0
		for _, wrapper := range wrappers {
			_ = wrapper.Close()
			if wrapper != nil && wrapper.state != nil {
				select {
				case <-wrapper.state.closeDone:
					closedWrappers++
				default:
				}
			}
		}
		for position := range childResults {
			if consumed[position] {
				continue
			}
			if childResults[position].Token != (personal.VaultFileChildToken{}) {
				_ = parent.LockVaultFileChild(childResults[position].Token)
			}
			clearLocalGenesisItems(childResults[position].Items)
			childResults[position] = personal.OwnedVaultFileChildResult{}
		}
		for index := range results {
			clearLocalGenesisItems(results[index].Baseline.Items)
			results[index] = LocalGenesisBatchResult{}
		}
		summariesCleared := true
		for index := range results {
			if results[index].Wrapper != nil || results[index].Baseline.VaultID != "" ||
				len(results[index].Baseline.Items) != 0 || results[index].Err != nil {
				summariesCleared = false
				break
			}
		}
		if localGenesisBatchCleanupForTest != nil {
			localGenesisBatchCleanupForTest(closedWrappers, summaryBuffers, summariesCleared)
		}
		parent.Lock()
		return nil, nil, err
	}
	localError := func(indices []int) {
		for _, index := range indices {
			results[index].Err = ErrLocalReview
		}
	}

	for _, group := range groups {
		if group.err != nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return cleanup(err)
		}
		position := group.targetPosition
		result := childResults[position]
		if result.Err != nil {
			if result.Token != (personal.VaultFileChildToken{}) {
				_ = parent.LockVaultFileChild(result.Token)
			}
			consumed[position] = true
			clearLocalGenesisItems(result.Items)
			childResults[position] = personal.OwnedVaultFileChildResult{}
			localError(group.indices)
			continue
		}
		if result.Token == (personal.VaultFileChildToken{}) {
			consumed[position] = true
			clearLocalGenesisItems(result.Items)
			childResults[position] = personal.OwnedVaultFileChildResult{}
			localError(group.indices)
			continue
		}
		if _, exists := wrappedTokens[result.Token]; exists {
			return cleanup(ErrLocalReview)
		}

		manifest, digest, companion, locatorErr := readLocalGenesisLocatorForAccount(
			accountPath, group.locator.configPath, group.locator.workspaceRoot,
			group.locator.vaultID, group.locator.journalPath)
		if locatorErr != nil || manifest != group.manifest || digest != group.digest ||
			!SameCompanion(companion, group.companion) {
			_ = parent.LockVaultFileChild(result.Token)
			consumed[position] = true
			clearLocalGenesisItems(result.Items)
			childResults[position] = personal.OwnedVaultFileChildResult{}
			localError(group.indices)
			continue
		}
		verified, verifyErr := verifyLocalGenesisCompanion(manifest, companion)
		if verifyErr != nil || verified.revision != group.revision ||
			!sameLocalGenesisSuccessor(verified.successor, group.successor) {
			clearLocalGenesisVerified(&verified)
			_ = parent.LockVaultFileChild(result.Token)
			consumed[position] = true
			clearLocalGenesisItems(result.Items)
			childResults[position] = personal.OwnedVaultFileChildResult{}
			localError(group.indices)
			continue
		}
		clearLocalGenesisVerified(&verified)

		state := &localGenesisSessionState{
			parent: parent, configPath: group.locator.configPath,
			manifest: group.manifest, manifestSHA256: group.digest,
			companion: cloneLocalGenesisCompanion(group.companion),
			revision:  group.revision, successor: cloneLocalGenesisSuccessor(group.successor),
			token:     result.Token,
			closeDone: make(chan struct{}),
		}
		wrapper := &LocalGenesisSession{state: state}
		summary, summaryErr := state.initialSummary(result.Items)
		consumed[position] = true
		childResults[position] = personal.OwnedVaultFileChildResult{}
		if summaryErr != nil || summary.VaultID != group.manifest.VaultID {
			_ = state.close()
			localError(group.indices)
			continue
		}
		wrappedTokens[result.Token] = wrapper
		wrappers = append(wrappers, wrapper)
		for _, index := range group.indices {
			results[index].Wrapper = wrapper
			results[index].Baseline = LocalGenesisBaseline{
				VaultID: summary.VaultID,
				Items:   cloneLocalGenesisBatchItems(summary.Items),
			}
		}
		clearLocalGenesisItems(summary.Items)
	}
	for position := range consumed {
		if !consumed[position] {
			return cleanup(ErrLocalReview)
		}
	}

	if localGenesisBatchBeforeDeliveryForTest != nil {
		localGenesisBatchBeforeDeliveryForTest()
	}
	if err := ctx.Err(); err != nil {
		return cleanup(err)
	}
	if !parent.Unlocked() {
		return cleanup(ErrLocalReview)
	}
	return parent, results, nil
}
