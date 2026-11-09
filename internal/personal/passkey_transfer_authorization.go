package personal

import (
	"errors"
	"time"
)

// ErrFullFactorRequired is the fixed refusal for a passkey transfer operation
// requested by an unlocked session that has no fresh full-factor proof. The
// session itself may be usable for ordinary reads and edits, so this is
// deliberately distinct from ErrSessionLocked: the caller must perform an
// explicit full UnlockSession (master password and Secret Key) before any
// transfer action. No result is disclosed, invitation consumed or state
// committed when it is returned. A final expiry check may follow internal
// decryption; that private intermediate is cleared before returning.
var ErrFullFactorRequired = errors.New("fresh full-factor unlock required for passkey transfer")

// passkeyTransferFullFactorWindow is the explicit maximum age of the
// full-factor unlock that authorizes any passkey transfer operation:
// invitation creation, invitation revocation, sealed export, read-only plan and
// import/apply.
//
// Transfer is the only personal flow that extracts reusable WebAuthn private
// keys from this vault (export) or folds a foreign credential set into it
// (import), so it never accepts the weaker proof that ordinary vault reads and
// edits accept. The window deliberately matches the two existing native bounds
// rather than inventing a third lifetime: the maximum session idle accepted by
// UnlockSession (15 minutes) and the maximum invitation TTL accepted by
// newPasskeyTransferInvitation (15 minutes).
//
// It is measured from the full-factor unlock itself:
//
//   - ordinary activity after unlock (every active(true) that refreshes
//     Session.last for idle expiry) must not extend it, so a session kept warm
//     by reads or edits cannot keep transfer authority alive;
//   - OS quick unlock (UnlockWithSystem) leaves Session.fullUnlock zero. A
//     quick-unlock session therefore never satisfies this check, and
//     EnableSystemUnlock must not copy its enrollment timestamp back into a
//     later session as if it were a new full-factor proof;
//   - a zero or future fullUnlock timestamp fails closed.
//
// The only way to refresh transfer authority is a new explicit full unlock.
const passkeyTransferFullFactorWindow = 15 * time.Minute

// requireFreshFullFactor is the single authorization check shared by every
// passkey transfer entry point. Callers must hold Session.mu — fullUnlock is
// only ever read or written under that mutex — and must call it before the
// vault database is opened, before a packet is decrypted or new output is
// released, and again immediately before winning the commit gate so a long
// transaction cannot commit after the proof expired.
func (s *Session) requireFreshFullFactor() error {
	if s == nil || s.fullUnlock.IsZero() {
		return ErrFullFactorRequired
	}
	age := time.Since(s.fullUnlock)
	if age < 0 || age >= passkeyTransferFullFactorWindow {
		return ErrFullFactorRequired
	}
	return nil
}
