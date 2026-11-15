package vaultfilejournal

import "errors"

var (
	// ErrTargetExists reports an exclusive-create collision. The existing
	// target was never opened, initialized, repaired or overwritten.
	ErrTargetExists = errors.New("vault file journal: target exists")
	// ErrCreateUnknown reports that creating the new journal may have had a
	// durable effect. The target is retained, including on initialization,
	// sync or close failure. Never erase it or infer success from a readback.
	ErrCreateUnknown = errors.New("vault file journal: creation outcome unknown")
)

// CreateNewState creates exactly one new private journal with an initial
// State: Generation 0, matching nonempty BaseBytes/WorkingBytes and a nonempty
// remote revision. The existing private parent must be owned by the operator;
// no directories are created or permissions repaired. Every existing target,
// including an empty, corrupt or symlinked target, is ErrTargetExists.
//
// The exclusively created, mode-0600 descriptor is the only file bbolt uses.
// The validated parent descriptor binds both creation and directory sync.
// Normal synchronous InitializeEmptyState, identity checks, parent sync and
// close must all succeed before nil is returned. After creation every failure
// is ErrCreateUnknown and leaves the target for review; a repeated call refuses
// the existing path. This does not authenticate state bytes or prove freshness.
//
// Implemented on Darwin and Linux only. Other platforms return ErrUnsupported.
// As with OpenExisting, cooperating writers are isolated; arbitrary same-owner
// changes outside the locking protocol are not a namespace lease.
func CreateNewState(path string, state State) error {
	return createNewState(path, state)
}
