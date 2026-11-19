package brokerlease

import "encoding/json"

// MetadataVersion is the fixed schema version of the diagnostic record.
const MetadataVersion = 1

// MaxRecordBytes is the hard upper bound of one encoded diagnostic record.
// There is no external profile or configuration that can raise it.
const MaxRecordBytes = 256

// MaxBindingChecks is the fixed upper bound for the diagnostic binding-check
// count. It matches the twelve fields in Binding and cannot be configured.
const MaxBindingChecks = 12

// Fixed diagnostic errors. None of them includes input text, values, labels,
// identities, or a wrapped cause.
var (
	ErrMetadataEvent         = newMetadataError("brokerlease: metadata event rejected")
	ErrMetadataReason        = newMetadataError("brokerlease: metadata reason rejected")
	ErrMetadataBindingChecks = newMetadataError("brokerlease: metadata binding-check count rejected")
	ErrMetadataNonceConsumed = newMetadataError("brokerlease: metadata nonce count rejected")
	ErrMetadataEncode        = newMetadataError("brokerlease: metadata encoding failed")
	ErrMetadataSize          = newMetadataError("brokerlease: metadata record too large")
)

type metadataError string

func (e metadataError) Error() string { return string(e) }

func newMetadataError(text string) error { return metadataError(text) }

// Event is the closed set of diagnostic event categories. EventUnknown is
// invalid; every valid event is a label only, not proof of authentication,
// approval, delivery, success, or failure.
type Event uint8

const (
	EventUnknown Event = iota
	EventLeasePending
	EventLeaseActivated
	EventLeaseUsed
	EventLeaseRefused
	EventLeaseExpired
	EventLeaseRevoked
	EventLeaseClosing
	EventLeaseClosed
	EventLeaseRefreshPending
	EventLeaseOutcomeUnknown

	eventFirst = EventLeasePending
	eventLast  = EventLeaseOutcomeUnknown
)

func (e Event) label() (string, bool) {
	switch e {
	case EventLeasePending:
		return "lease_pending", true
	case EventLeaseActivated:
		return "lease_activated", true
	case EventLeaseUsed:
		return "lease_used", true
	case EventLeaseRefused:
		return "lease_refused", true
	case EventLeaseExpired:
		return "lease_expired", true
	case EventLeaseRevoked:
		return "lease_revoked", true
	case EventLeaseClosing:
		return "lease_closing", true
	case EventLeaseClosed:
		return "lease_closed", true
	case EventLeaseRefreshPending:
		return "lease_refresh_pending", true
	case EventLeaseOutcomeUnknown:
		return "lease_outcome_unknown", true
	default:
		return "", false
	}
}

// Reason is the closed set of diagnostic reason categories. ReasonUnknown is
// invalid and ReasonNone is the explicit no-reason member. A reason is a label
// only and does not establish a security outcome.
type Reason uint8

const (
	ReasonUnknown Reason = iota
	ReasonNone
	ReasonState
	ReasonBinding
	ReasonDeadline
	ReasonClock
	ReasonExpired
	ReasonNonceReplay
	ReasonNonceCapacity
	ReasonUnknownOutcome
	ReasonRefreshScope
	ReasonRefreshVersion

	reasonFirst = ReasonNone
	reasonLast  = ReasonRefreshVersion
)

func (r Reason) label() (string, bool) {
	switch r {
	case ReasonNone:
		return "none", true
	case ReasonState:
		return "state", true
	case ReasonBinding:
		return "binding", true
	case ReasonDeadline:
		return "deadline", true
	case ReasonClock:
		return "clock", true
	case ReasonExpired:
		return "expired", true
	case ReasonNonceReplay:
		return "nonce_replay", true
	case ReasonNonceCapacity:
		return "nonce_capacity", true
	case ReasonUnknownOutcome:
		return "unknown_outcome", true
	case ReasonRefreshScope:
		return "refresh_scope", true
	case ReasonRefreshVersion:
		return "refresh_version", true
	default:
		return "", false
	}
}

// Metadata is the complete accepted input of one diagnostic encoding. It has
// only closed enums and bounded counts. It cannot carry arbitrary strings,
// bytes, maps, slices, interfaces, errors, callbacks, identities, digests,
// nonces, handles, paths, timestamps, Binding, Lease, Permit, or secret
// payload. The encoded record is diagnostics only: it is not a security audit,
// authentication proof, or evidence that a lease operation succeeded.
type Metadata struct {
	Event         Event
	Reason        Reason
	BindingChecks uint8
	NonceConsumed uint16
}

type metadataRecord struct {
	V             int    `json:"v"`
	Event         string `json:"event"`
	Reason        string `json:"reason"`
	BindingChecks uint8  `json:"binding_checks"`
	NonceConsumed uint16 `json:"nonce_consumed"`
}

// Encode validates the closed enums and fixed count bounds and returns one
// deterministic JSON record. It performs no IO, creates no file, writes no
// stdout, and uses no network. It is not a logger and accepts no arbitrary
// object. Invalid input returns a fixed sentinel with a nil byte slice.
func Encode(m Metadata) ([]byte, error) {
	event, eventOK := m.Event.label()
	if !eventOK {
		return nil, ErrMetadataEvent
	}
	reason, reasonOK := m.Reason.label()
	if !reasonOK {
		return nil, ErrMetadataReason
	}
	if m.BindingChecks > MaxBindingChecks {
		return nil, ErrMetadataBindingChecks
	}
	if m.NonceConsumed > MaxAdmissionsPerLease {
		return nil, ErrMetadataNonceConsumed
	}
	raw, err := json.Marshal(metadataRecord{
		V:             MetadataVersion,
		Event:         event,
		Reason:        reason,
		BindingChecks: m.BindingChecks,
		NonceConsumed: m.NonceConsumed,
	})
	if err != nil {
		return nil, ErrMetadataEncode
	}
	if len(raw) > MaxRecordBytes {
		return nil, ErrMetadataSize
	}
	return raw, nil
}
