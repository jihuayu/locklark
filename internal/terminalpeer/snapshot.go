package terminalpeer

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Fixed observation errors. Callers must use errors.Is and must not add
// authority because an observation succeeded.
var (
	// ErrUnavailable reports that the platform, build, descriptor, or kernel
	// call cannot establish an observation.
	ErrUnavailable = errors.New("terminal peer observation unavailable")

	// ErrMalformed reports kernel data that is not a well-formed observation:
	// a relative or non-clean path, a non-positive PID or pidversion, or a
	// zero or out-of-range start time.
	ErrMalformed = errors.New("terminal peer observation malformed")

	// ErrMismatch reports that the observed socket, token, credential,
	// generation, start pair, or controlling terminal changed.
	ErrMismatch = errors.New("terminal peer observation changed")
)

// maxTokenPath bounds a pathname accepted from proc_pidpath_audittoken. It is
// PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN) on the validated SDK.
const maxTokenPath = 4096

// tokenWords is the public audit_token_t layout: eight unsigned 32-bit words.
const tokenWords = 8

// peerToken is the complete 32-byte audit token, compared exactly.
type peerToken [tokenWords]uint32

// socketID identifies the local AF_UNIX socket object. A duplicated descriptor
// of the same socket has the same identity; a different connection does not.
type socketID struct {
	dev uint64
	ino uint64
}

// peerSample is one token plus the path the kernel resolves for that exact
// pidversion. It contains no PROC_PIDTBSDINFO credential.
type peerSample struct {
	token      peerToken
	path       string
	pid        int32
	pidVersion int32
	euid       uint32
}

// peerCredential is the PROC_PIDTBSDINFO view of one PID. The kernel's
// pbi_uid is the effective UID; the structure has no separate pbi_euid field.
// The start pair is pbi_start_tvsec/pbi_start_tvusec, and e_tdev is the
// session controlling-terminal device (0xffffffff when there is none).
type peerCredential struct {
	pid       int32
	euid      uint32
	startSec  uint64
	startUsec uint64
	ttyDev    uint32
}

// observed is one bounded observation. It is deliberately unexported so the
// package cannot accidentally become a serializable peer record.
type observed struct {
	token      peerToken
	path       string
	pid        int32
	pidVersion int32
	euid       uint32
	startSec   uint64
	startUsec  uint64
	ttyDev     uint32
}

// observationState holds the bounded observation behind an opaque handle.
// Keeping it behind one pointer means fmt reflection cannot walk into token,
// socket, PID, pidversion, path, start, or TTY fields if a special fmt path
// bypasses Formatter.
type observationState struct {
	socket   socketID
	observed observed
}

// Observation is an opaque, per-connection observational snapshot. It is not
// an authorization token, an image identity, a lease, or reusable approval
// evidence. Its only reflectable field is the opaque state handle; formatting
// yields a fixed name for every Formatter-dispatched verb.
type Observation struct {
	state *observationState
}

// Observe captures one observational snapshot of an already-connected Unix
// peer. It reads a token and its token-bound path, then PROC_PIDTBSDINFO for
// the token's PID, then the token and path again. The two token samples must
// be identical and their token-bound paths must be identical; the PID and
// effective UID must agree with PROC_PIDTBSDINFO. Any disagreement is
// ErrMismatch. Unsupported builds and failed kernel calls are ErrUnavailable.
//
// The two samples bound the reads but do not make them atomic. In particular,
// this does not prove the process generation that originally connected, and a
// token-bound path is not image contents or a signature.
func Observe(conn *net.UnixConn) (Observation, error) {
	if conn == nil {
		return Observation{}, ErrUnavailable
	}
	before, err := socketIdentity(conn)
	if err != nil {
		return Observation{}, ErrUnavailable
	}
	first, err := readPeerSample(conn)
	if err != nil {
		return Observation{}, err
	}
	cred, err := readPeerCredential(first.pid)
	if err != nil {
		return Observation{}, err
	}
	second, err := readPeerSample(conn)
	if err != nil {
		return Observation{}, err
	}
	after, err := socketIdentity(conn)
	if err != nil {
		return Observation{}, ErrUnavailable
	}
	if before != after {
		return Observation{}, ErrMismatch
	}
	if first != second {
		return Observation{}, ErrMismatch
	}
	if first.pid != cred.pid || first.euid != cred.euid {
		return Observation{}, ErrMismatch
	}
	raw := observed{
		token:      second.token,
		path:       second.path,
		pid:        second.pid,
		pidVersion: second.pidVersion,
		euid:       second.euid,
		startSec:   cred.startSec,
		startUsec:  cred.startUsec,
		ttyDev:     cred.ttyDev,
	}
	if err := validateObserved(raw, uint32(os.Geteuid())); err != nil {
		return Observation{}, err
	}
	return Observation{state: &observationState{socket: before, observed: raw}}, nil
}

// Revalidate re-reads the same socket and rejects any observed change to the
// socket object, token, effective UID, pidversion, start pair, or controlling
// terminal. It also requires the token-bound path to remain identical. It
// reads the token and path once before and once after PROC_PIDTBSDINFO, just
// as Observe does.
//
// Revalidation is still observational and non-atomic. It does not prove the
// original connector, image authenticity, or a lease. It must not be used to
// create or extend authority.
func (o Observation) Revalidate(conn *net.UnixConn) error {
	if conn == nil || o.state == nil {
		return ErrUnavailable
	}
	before, err := socketIdentity(conn)
	if err != nil {
		return ErrUnavailable
	}
	if before != o.state.socket {
		return ErrMismatch
	}
	first, err := readPeerSample(conn)
	if err != nil {
		return ErrMismatch
	}
	cred, err := readPeerCredential(first.pid)
	if err != nil {
		return ErrMismatch
	}
	second, err := readPeerSample(conn)
	if err != nil {
		return ErrMismatch
	}
	after, err := socketIdentity(conn)
	if err != nil {
		return ErrUnavailable
	}
	if after != o.state.socket {
		return ErrMismatch
	}
	if first != second {
		return ErrMismatch
	}
	if first.pid != cred.pid || first.euid != cred.euid {
		return ErrMismatch
	}
	raw := observed{
		token:      second.token,
		path:       second.path,
		pid:        second.pid,
		pidVersion: second.pidVersion,
		euid:       second.euid,
		startSec:   cred.startSec,
		startUsec:  cred.startUsec,
		ttyDev:     cred.ttyDev,
	}
	if !sameObserved(raw, o.state.observed) {
		return ErrMismatch
	}
	if raw.euid != uint32(os.Geteuid()) {
		return ErrMismatch
	}
	return nil
}

// observationText is the only text Formatter emits for an Observation.
const observationText = "terminalpeer.Observation"

// String keeps an accidental formatting of an Observation from disclosing the
// token, PID, pidversion, start pair, TTY device, or path.
func (Observation) String() string { return observationText }

// GoString keeps %#v formatting on the same fixed text.
func (Observation) GoString() string { return observationText }

// Format makes every verb that fmt dispatches to Formatter opaque. It writes
// only observationText and deliberately ignores the verb, flags, width, and
// precision, so numeric, character, quoted, flag, width, precision, and
// invalid verbs cannot recurse into Observation fields.
//
// fmt handles %T and %p before Formatter. %T emits only the type name; %p on
// a pointer emits only its address. Neither path reaches the state fields, but
// this package does not claim those two special verbs are fixed bytes. %p on a
// non-pointer value falls through fmt's bad-verb path to %v, which reaches
// Format and therefore remains opaque.
//
// fmt also handles %w specially when the argument is not an error: its
// bad-verb path bypasses Formatter and may render the opaque state handle. It
// still cannot reach the token, socket, PID, pidversion, path, start, or TTY
// fields behind that handle, so this package does not claim %w is fixed bytes.
func (Observation) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(observationText))
}

// sameObserved compares every bounded observation field exactly.
func sameObserved(a, b observed) bool {
	return a.token == b.token &&
		a.path == b.path &&
		a.pid == b.pid &&
		a.pidVersion == b.pidVersion &&
		a.euid == b.euid &&
		a.startSec == b.startSec &&
		a.startUsec == b.startUsec &&
		a.ttyDev == b.ttyDev
}

// validateObserved rejects malformed kernel data before it becomes an
// Observation. Credential disagreement is a mismatch, not malformed data.
func validateObserved(o observed, expectedEUID uint32) error {
	if o.pid <= 0 || o.pidVersion <= 0 {
		return ErrMalformed
	}
	if o.startSec == 0 || o.startUsec >= 1_000_000 {
		return ErrMalformed
	}
	if o.ttyDev == 0 || o.ttyDev == math.MaxUint32 {
		// No controlling terminal is an unavailable observation, not a
		// malformed token or path.
		return ErrUnavailable
	}
	if !validTokenPath(o.path) {
		return ErrMalformed
	}
	if o.euid != expectedEUID {
		return ErrMismatch
	}
	return nil
}

// validTokenPath checks only the shape of a kernel-returned pathname. It is
// not image trust: it does not stat, hash, sign, or resolve the path.
func validTokenPath(path string) bool {
	if path == "" || len(path) > maxTokenPath {
		return false
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return false
	}
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}
