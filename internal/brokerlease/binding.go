package brokerlease

// Binding is a secret-free, immutable observation supplied by a trusted owner
// adapter. Its fixed-size fields describe the exact authority scope of one
// prospective lease. A digest here records what the owner observed; it is not
// proof of kernel identity, process identity, or caller authentication.
//
// The value has no maps, slices, pointers, passwords, keys, prepared values, or
// other payload fields. Copying a Binding therefore copies the complete
// observation, and comparing two Bindings compares every field.
type Binding struct {
	Vault             VaultID
	SnapshotEpoch     uint64
	Session           SessionID
	SessionGeneration uint64
	DesktopEpoch      uint64
	Item              ItemID
	Revision          RevisionID
	Field             Field
	Profile           ProfileID
	Caller            CallerID
	Terminal          TerminalID
	Execution         ExecutionScopeID
}

// VaultID is a fixed-size owner observation of one vault identity.
type VaultID [32]byte

// SessionID is a fixed-size owner observation of one parent session instance.
type SessionID [32]byte

// ItemID is a fixed-size owner observation of one item identity.
type ItemID [32]byte

// RevisionID is a fixed-size owner observation of one item revision.
type RevisionID [32]byte

// ProfileID is a fixed-size owner observation of one exact profile.
type ProfileID [32]byte

// CallerID is a fixed-size owner observation of an already-verified caller.
type CallerID [32]byte

// TerminalID is a fixed-size owner observation of an already-verified terminal.
type TerminalID [32]byte

// ExecutionScopeID is a fixed-size owner observation of the complete execution
// scope. The owner adapter is responsible for the canonical encoding.
type ExecutionScopeID [32]byte

// Field is the closed set of fields this core can bind. Unknown is invalid.
type Field uint8

const (
	FieldUnknown Field = iota
	FieldUsername
	FieldPassword
	FieldURL
	FieldNotes
	FieldAttachment
	FieldFilename
)

func (f Field) valid() bool {
	switch f {
	case FieldUsername, FieldPassword, FieldURL, FieldNotes, FieldAttachment, FieldFilename:
		return true
	default:
		return false
	}
}

// Valid reports whether every required identity field is present and the field
// is a known member of the closed set. Counters may be zero; they are owner
// observations bounded only by their fixed width.
func (b Binding) Valid() bool {
	return b.Vault != (VaultID{}) &&
		b.SnapshotEpoch > 0 &&
		b.Session != (SessionID{}) &&
		b.Item != (ItemID{}) &&
		b.Revision != (RevisionID{}) &&
		b.Field.valid() &&
		b.Profile != (ProfileID{}) &&
		b.Caller != (CallerID{}) &&
		b.Terminal != (TerminalID{}) &&
		b.Execution != (ExecutionScopeID{})
}

// Equal reports whether two observations are the same exact scope. It checks
// every field, including counters that might otherwise be treated as advisory.
func (b Binding) Equal(other Binding) bool {
	return b == other
}
