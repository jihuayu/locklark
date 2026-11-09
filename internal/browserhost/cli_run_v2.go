package browserhost

// CLI run v2 is a distinct, one-shot wire protocol. It is selected only by the
// exact BrokerHello{v:2, mode:"cli-run"} and never falls back to the legacy
// per-field v1 request path. Every public selector below is bounded and free of
// Unicode controls; no private vault record, snapshot or credential ever appears
// in a hello, challenge or scope.

import (
	"time"

	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
)

const (
	cliRunV2Version       = 2
	cliRunV2Mode          = "cli-run"
	cliRunV2NonceBytes    = 16
	cliRunV2NonceHexLen   = cliRunV2NonceBytes * 2
	cliRunV2MaxTargets    = 16
	cliRunV2MaxArgs       = 64
	cliRunV2MaxArgBytes   = 16 << 10
	cliRunV2MaxHelperPath = 16
	cliRunV2MaxPathBytes  = 4096
	cliRunV2MaxSlotBytes  = 128
	cliRunV2MaxProfileID  = 128
	cliRunV2MaxPass       = 32
	cliRunV2MaxValueBytes = 64 << 10
	// cliRunV2HandshakeTTL is the absolute per-connection window for the
	// challenge/request exchange. It is set once and never extended by a read.
	cliRunV2HandshakeTTL = 15 * time.Second
	// cliRunV2ApprovalTTL is the absolute ceiling a native callback may take
	// before delivering values. A request can never reset it.
	cliRunV2ApprovalTTL = 30 * time.Second
	// cliRunV2WriteTimeout bounds the single owned reply write.
	cliRunV2WriteTimeout = 250 * time.Millisecond
)

// cliRunV2Fields is the canonical public field selector set. The trusted
// personal profile still decides which fields a slot kind may use.
var cliRunV2Fields = map[string]bool{
	"username": true, "password": true, "url": true, "notes": true,
	"attachment": true, "filename": true,
}

// CLIRunV2Target is one public selector: a profile slot bound to a vault item
// field. IDs and revisions are canonical lowercase hex, never private records.
type CLIRunV2Target struct {
	Slot     string `json:"slot"`
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Field    string `json:"field"`
}

// CLIRunV2Request is the bounded public wire request. It carries only what the
// broker needs to reconstruct the trusted profile policy; it never carries a
// caller-supplied cliprofile.Spec. ProfileID is the human profile name and
// SpecID/SpecDigest pin the exact versioned built-in policy the client used, so
// a mixed CLI/desktop pair that shares a profile name but renders a different
// spec can never agree on a scope.
type CLIRunV2Request struct {
	V              int               `json:"v"`
	Nonce          string            `json:"nonce"`
	Epoch          uint64            `json:"epoch"`
	VaultPath      string            `json:"vault_path"`
	Root           string            `json:"root"`
	ProfileID      string            `json:"profile_id"`
	SpecID         string            `json:"spec_id"`
	SpecDigest     string            `json:"spec_digest"`
	Program        string            `json:"program"`
	Args           []string          `json:"args"`
	Directory      string            `json:"directory"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	HelperPath     []string          `json:"helper_path,omitempty"`
	Passthrough    map[string]string `json:"passthrough,omitempty"`
	TokenEnvName   string            `json:"token_env_name,omitempty"`
	Targets        []CLIRunV2Target  `json:"targets"`
}

// CLIRunV2Params are the caller's client-private inputs. The per-connection
// nonce and current session epoch are filled from the server challenge, never
// chosen by the caller. The caller cannot supply a profile version, spec digest
// or spec: those are computed from the local built-in registry by profile name.
type CLIRunV2Params struct {
	VaultPath      string
	Root           string
	ProfileID      string
	Program        string
	Args           []string
	Directory      string
	TimeoutSeconds int
	HelperPath     []string
	Passthrough    map[string]string
	TokenEnvName   string
	Targets        []CLIRunV2Target
}

// CLIRunV2Challenge is emitted exactly once per connection before any request
// is accepted. It binds the authenticated OS peer, the current native session
// epoch and a fresh cryptographic nonce under an absolute deadline.
type CLIRunV2Challenge struct {
	V     int    `json:"v"`
	Nonce string `json:"nonce"`
	Epoch uint64 `json:"epoch"`
	Error string `json:"error,omitempty"`
}

// CLIRunV2Receipt is the canonical non-secret authorization binding. It never
// claims that a process ran.
type CLIRunV2Receipt struct {
	Session      string `json:"session"`
	Intent       string `json:"intent"`
	TargetDigest string `json:"target_digest"`
}

// CLIRunV2Reply is the single fixed frame written once. Values, when present,
// are the only secret-bearing part and are bounded by the request slots.
type CLIRunV2Reply struct {
	V           int               `json:"v"`
	Nonce       string            `json:"nonce"`
	Epoch       uint64            `json:"epoch"`
	ScopeDigest string            `json:"scope_digest,omitempty"`
	Receipt     *CLIRunV2Receipt  `json:"receipt,omitempty"`
	Values      map[string][]byte `json:"values,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// CLIRunV2Result is the verified client success payload handed to the next CLI
// provider stage. The caller owns Values and must zero it when done.
type CLIRunV2Result struct {
	Values      map[string][]byte
	Receipt     CLIRunV2Receipt
	ScopeDigest string
	Epoch       uint64
}

// CLIRunV2Scope is the trusted, reconstructed authorization scope shown to the
// native approval callback. It holds no credential bytes.
type CLIRunV2Scope struct {
	Peer        Peer
	VaultPath   string
	Root        string
	ProfileID   string
	SpecID      string
	SpecDigest  string
	Spec        cliprofile.Spec
	Request     personal.RunBundleRequest
	Targets     []personal.BundleTarget
	Nonce       string
	Epoch       uint64
	ScopeDigest string
}

// NativeCLIRunV2 is the opaque callback result. It carries only the owning
// session, its one-use native grant and the optional final proof callbacks; it is
// never a map, snapshot or secret.
type NativeCLIRunV2 struct {
	Session *personal.Session
	Grant   *personal.NativeRunBundleGrant

	// Revalidate is the final proof check. The broker calls it outside any
	// session mutex after the native callback returned and before the grant is
	// consumed. It must never call a Session method, because a caller may also
	// use it while it already owns session state.
	Revalidate func() error
	// StillValid is the cheap, last-moment revocation check. The broker calls it
	// immediately before building the disclosure frame, while the session
	// consume mutex is held, so it must only inspect immutable proof state,
	// absolute deadlines and the lease cache; it must never touch a Session.
	StillValid func() error
}
