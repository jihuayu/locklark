package vaultfileclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
)

var (
	ErrCreateVerification = errors.New("VERIFY_REJECTED")
	ErrCreateUnknown      = errors.New("UNKNOWN_REVIEW")
	ErrCreateCancelled    = errors.New("CANCELLED")
	ErrCreateUnsupported  = errors.New("UNSUPPORTED")
)

// CreationContext owns one real full-factor personal Session and an exact
// durable create manifest. It holds no password, Secret Key or recovery kit.
// A cancelled, expired, failed or backup-required context cannot be reopened.
type CreationContext struct {
	configPath         string
	manifest           Manifest
	manifestSHA256     string
	fullFactorDeadline time.Time
	session            *personal.Session
	ready              bool // guarded by operationMu
	operationMu        sync.Mutex
	stateMu            sync.Mutex
	terminal           bool
	activeCancel       context.CancelFunc
	// Nil in production. Tests can cancel after an actual durable intent and
	// companion, without receiving factors, G or a backend capability.
	afterIntentForTest func()
}

// OpenCreation reserves an initial selector before any custody work, or reads
// an existing strict manifest. A proposal is only an untrusted phase-one
// template: its VaultID must be empty and an existing file must match exactly.
// SecretInput is the textual Secret Key, parsed here once for the real unlock.
func OpenCreation(configPath string, proposal *Manifest, password, secretInput []byte) (*CreationContext, error) {
	manifest, err := EnsureCreateManifest(configPath, proposal)
	if err != nil {
		return nil, err
	}
	digest, err := ReadManifestDigest(configPath, manifest)
	if err != nil {
		return nil, ErrLocalReview
	}
	key, err := personal.ParseSecret(string(secretInput))
	if err != nil {
		return nil, ErrCreateVerification
	}
	defer clear(key)
	ownedPassword := bytes.Clone(password)
	defer clear(ownedPassword)
	unlockStarted := time.Now()
	session, err := personal.UnlockSession(manifest.PersonalFile, ownedPassword, key, time.Minute)
	if err != nil {
		return nil, ErrCreateVerification
	}
	confirmed, err := ReadManifestDigest(configPath, manifest)
	if err != nil || confirmed != digest {
		session.Lock()
		return nil, ErrLocalReview
	}
	return &CreationContext{configPath: configPath, manifest: manifest,
		manifestSHA256: digest, fullFactorDeadline: unlockStarted.Add(15 * time.Minute), session: session}, nil
}

// EnsureCreateManifest performs only durable selector reservation or an exact
// template retry. It grants no Session or backend authority. The CLI may call
// it before prompting so a failed factor entry preserves the original ID.
func EnsureCreateManifest(configPath string, proposal *Manifest) (Manifest, error) {
	if !teamfiles.ValidPath(configPath) {
		return Manifest{}, ErrConfig
	}
	if proposal != nil && !ValidManifestPhase(configPath, *proposal, false, false) {
		return Manifest{}, ErrConfig
	}
	manifest, exists, err := ReadManifest(configPath)
	if err != nil {
		return Manifest{}, ErrLocalReview
	}
	if exists {
		if proposal != nil && !sameCreateTemplate(manifest, *proposal) {
			return Manifest{}, ErrLocalReview
		}
	} else {
		if proposal == nil {
			return Manifest{}, ErrLocalReview
		}
		manifest, err = ReserveManifest(configPath, *proposal)
		if err != nil {
			return Manifest{}, err
		}
	}
	return manifest, nil
}

func sameCreateTemplate(a, b Manifest) bool {
	return a.Version == b.Version && a.Kind == b.Kind && b.VaultID == "" &&
		a.PersonalFile == b.PersonalFile && a.BackendRoot == b.BackendRoot &&
		a.Name == b.Name && a.Journal == b.Journal && a.Archive == b.Archive
}

func (c *CreationContext) checkManifest() (string, error) {
	digest, err := ReadManifestDigest(c.configPath, c.manifest)
	if err != nil || digest != c.manifestSHA256 {
		return "", ErrLocalReview
	}
	return digest, nil
}

func (c *CreationContext) fresh() error {
	if c == nil || !time.Now().Before(c.fullFactorDeadline) || c.session.AuthorityDeadline().IsZero() {
		return ErrCreateVerification
	}
	return nil
}

// Cancel revokes the Session before waiting for any disk or backend work.
// An already claimed remote attempt can still have an unknown outcome.
func (c *CreationContext) Cancel() {
	if c == nil {
		return
	}
	c.stateMu.Lock()
	c.terminal = true
	cancel := c.activeCancel
	c.stateMu.Unlock()
	c.session.RequestLock()
	if cancel != nil {
		cancel()
	}
}

// Close can wait for an in-flight operation; callers must not hold a UI lock.
func (c *CreationContext) Close() {
	if c == nil {
		return
	}
	c.Cancel()
	c.operationMu.Lock()
	c.session.Lock()
	c.operationMu.Unlock()
}

type creationOperation struct {
	owner  *CreationContext
	ctx    context.Context
	cancel context.CancelFunc
	stop   func() bool
}

func (c *CreationContext) begin(ctx context.Context) (*creationOperation, error) {
	if c == nil || ctx == nil {
		return nil, ErrCreateCancelled
	}
	c.operationMu.Lock()
	c.stateMu.Lock()
	if c.terminal || ctx.Err() != nil {
		c.stateMu.Unlock()
		c.operationMu.Unlock()
		return nil, ErrCreateCancelled
	}
	opCtx, cancel := context.WithCancel(ctx)
	c.activeCancel = cancel
	c.stateMu.Unlock()
	return &creationOperation{owner: c, ctx: opCtx, cancel: cancel,
		stop: context.AfterFunc(ctx, c.Cancel)}, nil
}

// finish is the completion gate for public results. A cancellation after a
// possible durable write is unknown; it never reports a late success.
func (op *creationOperation) finish(err error, mayWrite, terminalOnSuccess bool) error {
	op.stop()
	c := op.owner
	// The Session methods gate their own effects, but path I/O after their
	// return can outlive the full-factor or idle deadline. Do not release a
	// successful result from this outer operation after that deadline.
	if err == nil {
		if freshErr := c.fresh(); freshErr != nil {
			if mayWrite {
				err = ErrCreateUnknown
			} else {
				err = freshErr
			}
		}
	}
	c.stateMu.Lock()
	cancelled := c.terminal || op.ctx.Err() != nil
	if cancelled {
		if mayWrite {
			err = ErrCreateUnknown
		} else {
			err = ErrCreateCancelled
		}
	}
	if err != nil || terminalOnSuccess {
		c.terminal = true
	}
	c.activeCancel = nil
	terminal := c.terminal
	c.stateMu.Unlock()
	op.cancel()
	if terminal {
		c.session.RequestLock()
	}
	c.operationMu.Unlock()
	return err
}

// Prepare authenticates local ownership and reports whether a separate,
// published recovery backup is still required. BackupRequired is terminal:
// after the backup workflow the user explicitly opens a new context.
func (c *CreationContext) Prepare(ctx context.Context) (backupRequired bool, err error) {
	op, err := c.begin(ctx)
	if err != nil {
		return false, err
	}
	if _, err = c.checkManifest(); err != nil {
		return false, op.finish(err, false, false)
	}
	projection, err := c.session.PrepareVaultFileOwnership(c.manifest.VaultID)
	if err != nil || projection.VaultID != c.manifest.VaultID {
		return false, op.finish(ErrCreateVerification, true, false)
	}
	if _, err = c.checkManifest(); err != nil {
		return false, op.finish(err, true, false)
	}
	if _, err = os.Lstat(c.manifest.Archive); os.IsNotExist(err) {
		companionPath, pathErr := CompanionPath(c.configPath)
		if pathErr != nil {
			return false, op.finish(pathErr, true, false)
		}
		if _, journalErr := os.Lstat(c.manifest.Journal); !os.IsNotExist(journalErr) {
			return false, op.finish(ErrLocalReview, true, false)
		}
		if _, companionErr := os.Lstat(companionPath); !os.IsNotExist(companionErr) {
			return false, op.finish(ErrLocalReview, true, false)
		}
		return true, op.finish(nil, true, true)
	} else if err != nil {
		return false, op.finish(ErrLocalReview, true, false)
	}
	c.ready = true
	return false, op.finish(nil, true, false)
}

func createOwnedFactors(password, secretInput, kit []byte) (ownedPassword, key, ownedKit []byte, err error) {
	ownedPassword = bytes.Clone(password)
	key, err = personal.ParseSecret(string(secretInput))
	if err != nil {
		clear(ownedPassword)
		return nil, nil, nil, ErrCreateVerification
	}
	ownedKit = bytes.Clone(kit)
	return ownedPassword, key, ownedKit, nil
}

// Complete uses only explicit short-lived factor copies. It never unlocks a
// new Session, and it never treats the local baseline as a current remote head.
func (c *CreationContext) Complete(ctx context.Context, password, secretInput, kit []byte) error {
	op, err := c.begin(ctx)
	if err != nil {
		return err
	}
	if !c.ready {
		return op.finish(ErrLocalReview, false, false)
	}
	pw, key, recovery, err := createOwnedFactors(password, secretInput, kit)
	if err != nil {
		return op.finish(err, false, false)
	}
	defer clear(pw)
	defer clear(key)
	defer clear(recovery)
	if _, err = c.checkManifest(); err != nil {
		return op.finish(err, false, false)
	}
	if err = c.fresh(); err != nil {
		return op.finish(err, false, false)
	}
	err = c.completeCreate(op.ctx, pw, key, recovery)
	return op.finish(err, true, false)
}

// Verify rechecks the exact local generation-0 baseline with this Session and
// independent recovery inputs. It proves neither Ack origin nor remote head.
func (c *CreationContext) Verify(ctx context.Context, password, secretInput, kit []byte) error {
	op, err := c.begin(ctx)
	if err != nil {
		return err
	}
	if !c.ready {
		return op.finish(ErrLocalReview, false, false)
	}
	pw, key, recovery, err := createOwnedFactors(password, secretInput, kit)
	if err != nil {
		return op.finish(err, false, false)
	}
	defer clear(pw)
	defer clear(key)
	defer clear(recovery)
	if _, err = c.checkManifest(); err != nil {
		return op.finish(err, false, false)
	}
	companion, exists, err := ReadCompanion(c.configPath, c.manifest)
	if err != nil || !exists {
		return op.finish(ErrLocalReview, false, false)
	}
	err = c.verifyCreateAcked(companion, pw, key, recovery)
	return op.finish(err, false, false)
}
