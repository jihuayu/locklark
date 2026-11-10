// Package mobilecore is the narrow, native-only gomobile binding for a personal
// offline vault. Team keys and network upload are deliberately separate.
package mobilecore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

var (
	errLocked      = errors.New("vault is locked; unlock again")
	errClosed      = errors.New("vault is closed")
	errInvalid     = errors.New("invalid mobile vault request")
	errConflict    = errors.New("item changed; refresh and review before retrying")
	errCancelled   = errors.New("operation cancelled before persistence")
	errUnknown     = errors.New("operation result unknown; inspect the vault before retrying")
	errExpired     = errors.New("disclosure expired or already consumed")
	errUnavailable = errors.New("vault or authenticated system storage unavailable")
	errExists      = errors.New("vault already exists; unlock the existing vault")
	errCapacity    = errors.New("too many pending disclosures; clear an existing disclosure")
	// errVaultCapacity is distinct from errInvalid: the vault is still
	// unlocked and unchanged, but the item would exceed the stored vault size.
	errVaultCapacity = errors.New("vault capacity exceeded; remove or shrink large items or attachments; nothing was saved")
)

const idle = 300 * time.Second

// Vault retains an unlocked identity, never the account unlock factors.
// op serializes workers; mu protects only short in-memory state transitions.
type Vault struct {
	*vaultState
	bound         bool
	expectedEpoch uint64
}

type vaultState struct {
	op              sync.Mutex
	mu              sync.Mutex
	path            string
	session         *personal.Session
	epoch           uint64
	closed          bool
	cancel          context.CancelFunc
	gate            *personal.MutationGate
	handles         map[*SecretValue]bool
	cleanups        []<-chan struct{}
	operationQueued func() // deterministic worker-queue barrier in tests
	lockWaiting     func() // deterministic lock barrier in tests
}

func Open(path string) (*Vault, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errInvalid
	}
	return &Vault{vaultState: &vaultState{path: path, handles: make(map[*SecretValue]bool)}}, nil
}

// CaptureOperation is a short, memory-only native UI call. Capture before
// dispatching work, then use only the returned view inside that worker. The
// controller retains the base Vault for lifecycle operations.
func (v *Vault) CaptureOperation() (*Vault, error) {
	if !v.ready() {
		return nil, errInvalid
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, errClosed
	}
	if v.bound && v.expectedEpoch != v.epoch {
		return nil, errCancelled
	}
	epoch := v.epoch
	if v.bound {
		epoch = v.expectedEpoch
	}
	return &Vault{vaultState: v.vaultState, bound: true, expectedEpoch: epoch}, nil
}
func (v *Vault) ready() bool             { return v != nil && v.vaultState != nil }
func GenerateSecretKey() ([]byte, error) { return personal.NewSecret() }
func FormatSecretKey(key []byte) string  { return personal.FormatSecret(key) }
func ParseSecretKey(text string) ([]byte, error) {
	key, e := personal.ParseSecret(text)
	if e != nil {
		return nil, errInvalid
	}
	return key, nil
}
func (*Vault) String() string               { return "[native mobile vault]" }
func (*Vault) GoString() string             { return "[native mobile vault]" }
func (*Vault) MarshalJSON() ([]byte, error) { return nil, errLocked }

// RequestLock immediately invalidates all results, including a pending OS load.
// Session's request path shares its final commit/delivery arbitration; cleanup
// runs separately and never delays lifecycle cancellation behind disk I/O.
func (v *Vault) RequestLock() {
	if !v.ready() {
		return
	}
	v.mu.Lock()
	v.epoch++
	s := v.session
	v.session = nil
	if v.cancel != nil {
		v.cancel()
		v.cancel = nil
	}
	if v.gate != nil {
		v.gate.Cancel()
		v.gate = nil
	}
	handles := v.handles
	v.handles = make(map[*SecretValue]bool)
	var done chan struct{}
	if s != nil || len(handles) != 0 {
		// Keep only outstanding cleanup work, even when a native lifecycle uses
		// RequestLock repeatedly without calling the blocking Lock method.
		pending := v.cleanups[:0]
		for _, prior := range v.cleanups {
			select {
			case <-prior:
			default:
				pending = append(pending, prior)
			}
		}
		v.cleanups = pending
		done = make(chan struct{})
		v.cleanups = append(v.cleanups, done)
	}
	v.mu.Unlock()
	if s != nil {
		s.RequestLock()
	}
	if done != nil {
		go func() {
			defer close(done)
			for h := range handles {
				h.Clear()
			}
			if s != nil {
				s.Lock()
			}
		}()
	}
}
func (v *Vault) Lock() {
	if !v.ready() {
		return
	}
	v.RequestLock()
	v.mu.Lock()
	hook := v.lockWaiting
	v.mu.Unlock()
	if hook != nil {
		hook()
	}
	v.op.Lock()
	defer v.op.Unlock()
	// An explicit unlock may overtake this mutex wait. Invalidate again while
	// owning the worker gate so Lock cannot return with that session installed.
	// If nothing overtook cleanup, preserve fresh views captured after the
	// initial invalidation instead of requiring another user unlock attempt.
	v.mu.Lock()
	overtaken := v.session != nil || len(v.handles) != 0
	v.mu.Unlock()
	if overtaken {
		v.RequestLock()
	}
	v.mu.Lock()
	cleanups := v.cleanups
	v.cleanups = nil
	v.mu.Unlock()
	for _, done := range cleanups {
		<-done
	}
}
func (v *Vault) Close() {
	if !v.ready() {
		return
	}
	v.mu.Lock()
	v.closed = true
	v.mu.Unlock()
	v.Lock()
}
func (v *Vault) IsUnlocked() bool {
	if !v.ready() {
		return false
	}
	v.mu.Lock()
	s := v.session
	closed := v.closed
	stale := v.bound && v.expectedEpoch != v.epoch
	v.mu.Unlock()
	return !closed && !stale && s != nil && s.Unlocked()
}

func sanitized(e error) error {
	if e == nil {
		return nil
	}
	switch {
	case errors.Is(e, personal.ErrConflict):
		return errConflict
	case errors.Is(e, personal.ErrMutationUnknown):
		return errUnknown
	case errors.Is(e, personal.ErrMutationCancelled):
		return errCancelled
	case errors.Is(e, personal.ErrSessionLocked):
		return errLocked
	case errors.Is(e, personal.ErrOTPTime):
		return errExpired
	case errors.Is(e, personal.ErrSnapshotCapacity), errors.Is(e, personal.ErrImportCapacity):
		// The vault stayed unlocked and unchanged; only the write is over its
		// stored capacity, so point at the fix instead of "invalid request".
		return errVaultCapacity
	case errors.Is(e, personal.ErrMutationRefused), errors.Is(e, personal.ErrSearchQuery):
		return errInvalid
	case errors.Is(e, personal.ErrNotFound):
		return errors.New("item no longer exists; refresh the vault")
	case errors.Is(e, personal.ErrTrashed):
		return errors.New("item is in trash")
	case errors.Is(e, personal.ErrOTPNotConfigured):
		return errors.New("no TOTP configured for this item")
	case errors.Is(e, os.ErrExist):
		return errExists
	default:
		return errUnavailable
	}
}
func (v *Vault) startLocked(expected uint64) (uint64, context.Context, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return 0, nil, errClosed
	}
	if v.epoch != expected {
		return 0, nil, errCancelled
	}
	if v.session != nil {
		return 0, nil, errInvalid
	}
	ctx, cancel := context.WithCancel(context.Background())
	v.cancel = cancel
	return v.epoch, ctx, nil
}
func (v *Vault) current(s *personal.Session, epoch uint64) bool {
	if !v.ready() {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return !v.closed && v.epoch == epoch && v.session == s && (!v.bound || v.expectedEpoch == epoch)
}

// grantDelivery is the delivery linearization point shared with RequestLock.
// All authenticated disk work has completed before this short in-memory grant.
// If this grant wins, a native UI must still reject any later stale generation.
func (v *Vault) grantDelivery(secret *SecretValue, from, until int64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.epoch != secret.epoch || v.session != secret.session || secret.cancelled.Load() || v.bound && v.expectedEpoch != secret.epoch {
		return errLocked
	}
	sample := time.Now()
	if secret.grantClock != nil {
		sample = secret.grantClock()
	}
	now := sample.UnixMilli()
	if now < from || now >= until {
		return errExpired
	}
	if !secret.session.Unlocked() {
		return errLocked
	}
	if secret.otpBounds != nil {
		if !secret.otpBounds.Check(sample) {
			return errExpired
		}
		// Native UI receives the last verified not-before sample, rather than
		// the beginning of an OTP period that would permit a later rollback.
		secret.from = secret.otpBounds.WallSample.UnixMilli()
	}
	return nil
}
func (v *Vault) active() (*personal.Session, uint64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, 0, errClosed
	}
	if v.session == nil {
		return nil, 0, errLocked
	}
	return v.session, v.epoch, nil
}

func (v *Vault) enterOperation() (uint64, error) {
	if !v.ready() {
		return 0, errInvalid
	}
	v.mu.Lock()
	epoch, closed := v.epoch, v.closed
	if v.bound {
		epoch = v.expectedEpoch
	}
	stale := v.epoch != epoch
	hook := v.operationQueued
	v.mu.Unlock()
	if closed {
		return 0, errClosed
	}
	if stale {
		return 0, errCancelled
	}
	if hook != nil {
		hook()
	}
	v.op.Lock()
	v.mu.Lock()
	cancelled := v.closed || v.epoch != epoch
	v.mu.Unlock()
	if cancelled {
		v.op.Unlock()
		return 0, errCancelled
	}
	return epoch, nil
}
func (v *Vault) Create(password, secretKey []byte) error {
	defer clear(password)
	defer clear(secretKey)
	epoch, e := v.enterOperation()
	if e != nil {
		return e
	}
	defer v.op.Unlock()
	epoch, ctx, e := v.startLocked(epoch)
	if e != nil {
		return e
	}
	if len(secretKey) != 16 || len(password) == 0 || len(password) > 1024 {
		return errInvalid
	}
	e = personal.Create(v.path, string(password), secretKey)
	if e != nil {
		return sanitized(e)
	}
	v.mu.Lock()
	current := !v.closed && v.epoch == epoch && ctx.Err() == nil
	v.mu.Unlock()
	if !current {
		return errUnknown
	}
	return nil
}
func (v *Vault) install(s *personal.Session, epoch uint64, ctx context.Context, e error) error {
	if e != nil {
		return sanitized(e)
	}
	v.mu.Lock()
	if v.closed || v.epoch != epoch || ctx.Err() != nil {
		v.mu.Unlock()
		s.Lock()
		return errCancelled
	}
	v.session = s
	v.cancel = nil
	v.mu.Unlock()
	return nil
}
func (v *Vault) Unlock(password, secretKey []byte) error {
	defer clear(password)
	defer clear(secretKey)
	epoch, e := v.enterOperation()
	if e != nil {
		return e
	}
	defer v.op.Unlock()
	epoch, ctx, e := v.startLocked(epoch)
	if e != nil {
		return e
	}
	if len(secretKey) != 16 || len(password) == 0 || len(password) > 1024 {
		return errInvalid
	}
	s, e := personal.UnlockSession(v.path, password, secretKey, idle)
	return v.install(s, epoch, ctx, e)
}

// SystemUnlockStore must be an authenticated local Keychain/Keystore adapter.
// Calls occur outside Vault.mu. It must never use a plaintext-file fallback.
type SystemUnlockStore interface {
	Store(id string, value []byte) error
	Load(id string) ([]byte, error)
	Delete(id string) error
}

func (v *Vault) EnableSystemUnlock(store SystemUnlockStore) error {
	_, e := v.enterOperation()
	if e != nil {
		return e
	}
	defer v.op.Unlock()
	s, epoch, e := v.active()
	if e != nil {
		return e
	}
	if store == nil {
		return errInvalid
	}
	e = s.EnableSystemUnlock(store)
	if !v.current(s, epoch) {
		return errCancelled
	}
	return sanitized(e)
}
func (v *Vault) UnlockWithSystem(store SystemUnlockStore) error {
	epoch, e := v.enterOperation()
	if e != nil {
		return e
	}
	defer v.op.Unlock()
	epoch, ctx, e := v.startLocked(epoch)
	if e != nil {
		return e
	}
	if store == nil {
		return errInvalid
	}
	s, e := personal.UnlockWithSystemContext(ctx, v.path, store, idle)
	return v.install(s, epoch, ctx, e)
}
func (v *Vault) DisableSystemUnlock(store SystemUnlockStore) error {
	_, e := v.enterOperation()
	if e != nil {
		return e
	}
	defer v.op.Unlock()
	v.mu.Lock()
	closed := v.closed
	v.mu.Unlock()
	if closed {
		return errClosed
	}
	if store == nil {
		return errInvalid
	}
	return sanitized(personal.DisableSystemUnlock(v.path, store))
}

type Row struct{ ID, Revision, Title, State string }
type Rows struct{ rows []Row }

func (r *Rows) Count() int {
	if r == nil {
		return 0
	}
	return len(r.rows)
}
func (r *Rows) At(index int) (*Row, error) {
	if r == nil || index < 0 || index >= len(r.rows) {
		return nil, errInvalid
	}
	row := r.rows[index]
	return &row, nil
}
func rowsResult(rows []personal.Row) *Rows {
	out := &Rows{rows: make([]Row, 0, len(rows))}
	for _, r := range rows {
		if r.Kind != "login" {
			continue
		}
		out.rows = append(out.rows, Row{r.ID, r.Revision, r.Title, r.State})
	}
	return out
}
func (v *Vault) List(state string) (*Rows, error) {
	_, e := v.enterOperation()
	if e != nil {
		return nil, e
	}
	defer v.op.Unlock()
	s, epoch, e := v.active()
	if e != nil {
		return nil, e
	}
	rows, e := s.List(state)
	if !v.current(s, epoch) {
		return nil, errLocked
	}
	if e != nil {
		return nil, sanitized(e)
	}
	return rowsResult(rows), nil
}
func (v *Vault) Search(query, state string) (*Rows, error) {
	_, e := v.enterOperation()
	if e != nil {
		return nil, e
	}
	defer v.op.Unlock()
	s, epoch, e := v.active()
	if e != nil {
		return nil, e
	}
	rows, e := s.Search(query, state)
	if !v.current(s, epoch) {
		return nil, errLocked
	}
	if e != nil {
		return nil, sanitized(e)
	}
	return rowsResult(rows), nil
}

type Receipt struct {
	ID, Revision        string
	Length, EntropyBits int
}

func receipt(r personal.GenerationReceipt) *Receipt {
	return &Receipt{r.ID, r.Revision, r.Profile.Length, r.Profile.EntropyBits}
}
func (v *Vault) mutation(work func(*personal.Session, *personal.MutationGate) (personal.GenerationReceipt, error)) (*Receipt, error) {
	_, e := v.enterOperation()
	if e != nil {
		return nil, e
	}
	defer v.op.Unlock()
	s, epoch, e := v.active()
	if e != nil {
		return nil, e
	}
	g := personal.NewMutationGate(time.Now().Add(30 * time.Second))
	v.mu.Lock()
	if v.closed || v.epoch != epoch || v.session != s {
		v.mu.Unlock()
		return nil, errCancelled
	}
	if e = s.RegisterMutation(g); e != nil {
		v.mu.Unlock()
		return nil, sanitized(e)
	}
	v.gate = g
	v.mu.Unlock()
	defer func() {
		g.Cancel()
		s.ReleaseMutation(g)
		v.mu.Lock()
		if v.gate == g {
			v.gate = nil
		}
		v.mu.Unlock()
	}()
	r, e := work(s, g)
	if !v.current(s, epoch) {
		if g.CommitWon() {
			return nil, errUnknown
		}
		return nil, errCancelled
	}
	if e != nil {
		return nil, sanitized(e)
	}
	return receipt(r), nil
}
func (v *Vault) CreateLogin(title, url string, username, password []byte) (*Receipt, error) {
	defer clear(username)
	defer clear(password)
	return v.mutation(func(s *personal.Session, g *personal.MutationGate) (personal.GenerationReceipt, error) {
		return s.SaveNativeLogin(personal.NativeLoginMetadata{Title: title, URL: url}, username, password, g)
	})
}
func (v *Vault) GenerateLogin(title, url string, username []byte, length int) (*Receipt, error) {
	defer clear(username)
	return v.mutation(func(s *personal.Session, g *personal.MutationGate) (personal.GenerationReceipt, error) {
		return s.GenerateNativeLogin(personal.NativeLoginMetadata{Title: title, URL: url}, username, length, g)
	})
}
func (v *Vault) EditField(id, revision, field string, value []byte) (*Receipt, error) {
	defer clear(value)
	return v.mutation(func(s *personal.Session, g *personal.MutationGate) (personal.GenerationReceipt, error) {
		next, e := s.EditNativeField(id, revision, field, value, g)
		return personal.GenerationReceipt{ID: id, Revision: next}, e
	})
}
func (v *Vault) RegeneratePassword(id, revision string, length int) (*Receipt, error) {
	return v.mutation(func(s *personal.Session, g *personal.MutationGate) (personal.GenerationReceipt, error) {
		return s.RegenerateNativePassword(id, revision, length, g)
	})
}
