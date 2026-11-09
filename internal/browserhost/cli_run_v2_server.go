package browserhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

// cliRunV2ChallengeState binds one encrypted nonce to the actual authenticated
// OS peer, the current native session epoch and an absolute deadline. It is
// private server state and never exposed on the wire.
type cliRunV2ChallengeState struct {
	nonce  string
	epoch  uint64
	peer   Peer
	expiry time.Time
}

func newCLIRunV2Nonce() (string, bool) {
	var raw [cliRunV2NonceBytes]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", false
	}
	nonce := hex.EncodeToString(raw[:])
	clear(raw[:])
	return nonce, true
}

// serveCLIRunV2 owns exactly one connection-level exchange: challenge, one
// strict request, one optional native approval, and at most one output frame.
// Any extra client byte, EOF or network error after the request cancels the
// approval context so a vanished client can never leave a ghost approval.
func (b *Broker) serveCLIRunV2(conn net.Conn, peer Peer) {
	// The handshake window is absolute: no read may extend it.
	handshakeExpiry := time.Now().Add(cliRunV2HandshakeTTL)
	_ = conn.SetDeadline(handshakeExpiry)

	if b.callbacks.PrepareCLIRunV2 == nil || b.callbacks.CurrentSession == nil {
		b.writeCLIRunV2ChallengeError(conn, "unsupported")
		return
	}
	session, epoch, ok := b.callbacks.CurrentSession()
	if !ok || session == nil || !session.Unlocked() {
		b.writeCLIRunV2ChallengeError(conn, "unsupported")
		return
	}
	nonce, ok := newCLIRunV2Nonce()
	if !ok {
		b.writeCLIRunV2ChallengeError(conn, "unsupported")
		return
	}
	state := cliRunV2ChallengeState{nonce: nonce, epoch: epoch, peer: peer, expiry: handshakeExpiry}
	raw, e := json.Marshal(CLIRunV2Challenge{V: cliRunV2Version, Nonce: nonce, Epoch: epoch})
	if e != nil {
		return
	}
	if e = writeFrame(conn, raw); e != nil {
		clear(raw)
		return
	}
	clear(raw)

	reqRaw, e := readFrame(conn, MaxInput)
	if e != nil {
		return
	}
	defer clear(reqRaw)
	req, e := decodeCLIRunV2Request(reqRaw)
	if e != nil {
		b.writeCLIRunV2Refusal(conn, state, "refused")
		return
	}
	// From here a read watcher owns the read side and writes have their own
	// per-write deadline. Clear both absolute handshake deadlines.
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})
	if req.Nonce != state.nonce || req.Epoch != state.epoch || !time.Now().Before(state.expiry) || state.peer != peer {
		b.writeCLIRunV2Refusal(conn, state, "refused")
		return
	}
	cur, curEpoch, curOK := b.callbacks.CurrentSession()
	if !curOK || cur == nil || cur != session || curEpoch != epoch || !cur.Unlocked() || req.VaultPath != cur.VaultPath() {
		b.writeCLIRunV2Refusal(conn, state, "refused")
		return
	}
	// Rebuild the trusted policy from the local built-in only. The wire must
	// pin both the versioned spec id and the canonical spec digest of that same
	// local built-in, so a same-name but different-profile-version peer is
	// refused here, before any callback or authority exists.
	request, targets, spec, ok := trustedCLIRunV2Request(req)
	if !ok {
		b.writeCLIRunV2Refusal(conn, state, "refused")
		return
	}
	digest := cliRunV2ScopeDigest(req)
	if digest == "" {
		b.writeCLIRunV2Refusal(conn, state, "refused")
		return
	}
	scope := CLIRunV2Scope{
		Peer: peer, VaultPath: req.VaultPath, Root: req.Root, ProfileID: req.ProfileID,
		SpecID: req.SpecID, SpecDigest: req.SpecDigest,
		Spec: spec, Request: request, Targets: targets, Nonce: nonce, Epoch: epoch,
		ScopeDigest: digest,
	}

	// The approval lifetime is absolute and starts now. Neither the request nor
	// a late read can reset it.
	approvalExpiry := time.Now().Add(cliRunV2ApprovalTTL)
	ctx, cancel := context.WithDeadline(context.Background(), approvalExpiry)
	defer cancel()

	// The watcher owns the read side. A byte, EOF or error means the client is
	// gone: cancel immediately instead of waiting for a native decision.
	go func() {
		var one [1]byte
		for {
			n, err := conn.Read(one[:])
			if n > 0 || err != nil {
				cancel()
				return
			}
		}
	}()

	type callbackResult struct {
		native *NativeCLIRunV2
		err    error
	}
	// Re-pin the exact live session, its vault path and the challenge epoch
	// immediately before the native callback can prepare a grant. A mismatch is
	// a fixed refusal with no callback at all.
	before, beforeEpoch, beforeOK := b.callbacks.CurrentSession()
	if !beforeOK || before == nil || before != cur || beforeEpoch != epoch || !before.Unlocked() || req.VaultPath != before.VaultPath() {
		b.writeCLIRunV2Refusal(conn, state, "refused")
		return
	}
	results := make(chan callbackResult, 1)
	go func() {
		native, err := b.callbacks.PrepareCLIRunV2(ctx, scope)
		results <- callbackResult{native: native, err: err}
	}()

	var native *NativeCLIRunV2
	var callbackErr error
	select {
	case out := <-results:
		native, callbackErr = out.native, out.err
	case <-ctx.Done():
		// The callback did not return before the deadline. Drain it in the
		// background and discard any grant it may still produce, so a late
		// approval can never outlive the client.
		go func() {
			out := <-results
			if out.native != nil && out.native.Grant != nil {
				out.native.Grant.Discard()
			}
		}()
		b.writeCLIRunV2Refusal(conn, state, "refused")
		return
	}
	if callbackErr != nil || native == nil || native.Session == nil || native.Grant == nil {
		if native != nil && native.Grant != nil {
			native.Grant.Discard()
		}
		b.writeCLIRunV2Refusal(conn, state, "refused")
		return
	}
	defer native.Grant.Discard()
	if native.Session != cur {
		b.writeCLIRunV2Refusal(conn, state, "refused")
		return
	}
	// The native callback must re-read its own proof before the one-use grant is
	// consumed. This call is outside every session mutex: the callback only
	// observes kernel/lease state and must never reenter the Session.
	if native.Revalidate != nil {
		if e := native.Revalidate(); e != nil {
			b.writeCLIRunV2Refusal(conn, state, "refused")
			return
		}
	}
	// Re-pin the live session and epoch after proof and before consuming the
	// one-use grant. This is the only session-state read in this phase; the
	// writer callback itself stays Session-free to keep the lock order simple.
	after, afterEpoch, afterOK := b.callbacks.CurrentSession()
	if !afterOK || after == nil || after != cur || afterEpoch != epoch || !after.Unlocked() || !time.Now().Before(approvalExpiry) {
		b.writeCLIRunV2Refusal(conn, state, "refused")
		return
	}

	var writeMu sync.Mutex
	writeMu.Lock()
	defer writeMu.Unlock()
	attempted := false
	deliverErr := native.Session.ConsumeRunBundleGrant(ctx, native.Grant, func(values map[string][]byte, receipt personal.RunBundleGrantReceipt) error {
		if ctx.Err() != nil || !time.Now().Before(approvalExpiry) {
			return personal.ErrRunCancelled
		}
		// Last-moment expiry/revocation check, immediately before any reply byte
		// is built. StillValid never touches a Session, so the cheap lock flag is
		// read separately with one atomic load. A lock that already won before the
		// grant claim never reaches this callback; a later lock still suppresses
		// the frame here instead of delivering bytes after the owner locked.
		if native.StillValid != nil {
			if e := native.StillValid(); e != nil {
				return ErrBrokerRefused
			}
		}
		if native.Session.RunBundleDeliveryRevoked() {
			return ErrBrokerRefused
		}
		frame, ok := buildCLIRunV2Reply(state, digest, targets, receipt, values)
		if !ok {
			return ErrBrokerRefused
		}
		defer clear(frame)
		// Re-read the lock flag immediately before the single write. The frame is
		// already built but not yet disclosed, so a lock that arrives here still
		// refuses; only a lock after this read cannot revoke the borrowed bytes.
		if native.Session.RunBundleDeliveryRevoked() {
			return ErrBrokerRefused
		}
		if e := conn.SetWriteDeadline(time.Now().Add(cliRunV2WriteTimeout)); e != nil {
			return ErrBrokerUnknown
		}
		attempted = true
		if e := writeFrame(conn, frame); e != nil {
			return ErrBrokerUnknown
		}
		return nil
	})
	if deliverErr != nil && !attempted {
		b.writeCLIRunV2Refusal(conn, state, "refused")
	}
}

// buildCLIRunV2Reply proves the callback returned exactly the requested slots
// within bounds and a canonical receipt, then serializes one bounded frame.
// Values are borrowed byte slices; json encodes them as base64 so arbitrary
// credential bytes survive without a lossy string conversion.
func buildCLIRunV2Reply(state cliRunV2ChallengeState, digest string, targets []personal.BundleTarget, receipt personal.RunBundleGrantReceipt, values map[string][]byte) ([]byte, bool) {
	if !validCLIRunV2Receipt(receipt) || digest == "" || len(values) != len(targets) {
		return nil, false
	}
	for _, target := range targets {
		value, ok := values[target.Slot]
		if !ok || len(value) > cliRunV2MaxValueBytes {
			return nil, false
		}
	}
	reply := CLIRunV2Reply{
		V: cliRunV2Version, Nonce: state.nonce, Epoch: state.epoch, ScopeDigest: digest,
		Receipt: &CLIRunV2Receipt{Session: receipt.Session, Intent: receipt.Intent, TargetDigest: receipt.TargetDigest},
		Values:  values,
	}
	raw, e := json.Marshal(reply)
	if e != nil || len(raw) == 0 || len(raw) > MaxOutput {
		return nil, false
	}
	return raw, true
}

func validCLIRunV2Receipt(receipt personal.RunBundleGrantReceipt) bool {
	return validCLIRunV2Hex(receipt.Session, 16) &&
		validCLIRunV2Hex(receipt.Intent, 32) &&
		validCLIRunV2Hex(receipt.TargetDigest, 32)
}

func (b *Broker) writeCLIRunV2ChallengeError(conn net.Conn, code string) {
	raw, e := json.Marshal(CLIRunV2Challenge{V: cliRunV2Version, Error: code})
	if e != nil {
		return
	}
	defer clear(raw)
	_ = conn.SetWriteDeadline(time.Now().Add(cliRunV2WriteTimeout))
	_ = writeFrame(conn, raw)
}

func (b *Broker) writeCLIRunV2Refusal(conn net.Conn, state cliRunV2ChallengeState, code string) {
	reply := CLIRunV2Reply{V: cliRunV2Version, Nonce: state.nonce, Epoch: state.epoch, Error: code}
	raw, e := json.Marshal(reply)
	if e != nil {
		return
	}
	defer clear(raw)
	_ = conn.SetWriteDeadline(time.Now().Add(cliRunV2WriteTimeout))
	_ = writeFrame(conn, raw)
}
