package desktop

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
)

// Explicit terminal/command lease for cli-run v2.
//
// A lease is an owner decision to let the same authenticated terminal repeat
// one exact command against one exact set of target fields for at most five
// minutes. It is an authorization cache, never a credential cache: entries hold
// only public, caller-visible metadata and never a value, snapshot or prepared
// grant. Nothing is persisted, nothing survives a lock, stop or session epoch
// change, and a match never extends the deadline.
//
// The stable terminal identity deliberately excludes PID and the peer start
// ticks: a lease is meant to let a *new* CLI process on the same terminal repeat
// the command. It does bind the broker UID, the controlling terminal, the
// session id, the session leader's birth ticks, and the actual CLI executable
// path and image digest. The one-shot approval, by contrast, is additionally
// rechecked against the exact per-connection identity (including PeerStart) that
// the owner saw.
//
// The kernel attestation and the program image hash are variables so the cache
// and App wiring can be tested with explicit public identities. They are not
// production authentication hooks: production always uses browserhost's Linux
// /proc attestation and the ordinary-file hasher below, and callers can never
// supply an identity.

const (
	// cliLeaseTTL is the absolute, non-extending lifetime of one terminal
	// command lease. No match, click or read may move an entry's deadline.
	cliLeaseTTL = 5 * time.Minute
	// cliLeaseMax bounds the resident cache. Expired entries are pruned before
	// the capacity decision; a cache full of live entries refuses a new lease
	// instead of evicting a still-valid owner approval.
	cliLeaseMax = 8
	// cliLeaseMaxProgramBytes bounds the ordinary program image we hash. A
	// larger image cannot be proven inside these bounds and is refused.
	cliLeaseMaxProgramBytes = 256 << 20
)

var (
	errCLILeaseFull  = errors.New("desktop: CLI lease cache is full")
	errCLILeaseStale = errors.New("desktop: CLI lease proof is stale")

	// cliLeaseAttest is browserhost.AttestCLITerminal in production. Tests may
	// replace it with an explicit public identity; it is not an authentication
	// hook and it never accepts caller-supplied identity data.
	cliLeaseAttest = browserhost.AttestCLITerminal
	// cliLeaseVerify re-reads and compares the exact per-connection identity
	// (including PeerStart) in production.
	cliLeaseVerify = browserhost.VerifyCLITerminal
	// cliLeaseHashProgram hashes the ordinary executable image in production.
	cliLeaseHashProgram = hashCLIProgram
	// cliLeaseNow is the clock used when no cache is attached (one-shot checks).
	cliLeaseNow = time.Now
	// cliHashProgramBeforeFinalLstat is an unexported test seam placed after the
	// read and descriptor stat but before the final path identity check.
	// Production leaves it as a no-op.
	cliHashProgramBeforeFinalLstat = func() {}
)

// cliLeaseTTLLabel is the exact, human-readable TTL shown in the native
// approval view. It is derived from cliLeaseTTL so the text can never drift from
// the enforced deadline.
func cliLeaseTTLLabel() string {
	return intString(int(cliLeaseTTL/time.Minute)) + " 分钟（" + intString(int(cliLeaseTTL/time.Second)) + " 秒）"
}

// cliLeaseTerminal is the stable, public part of a kernel-attested terminal. It
// excludes PID and PeerStart so a new CLI process on the same terminal can match
// an existing lease; it binds the session leader birth so a recycled session or
// terminal can never match.
type cliLeaseTerminal struct {
	UID                uint32
	TTYDevice          uint64
	SessionID          uint32
	SessionLeaderStart uint64
	ExecutablePath     string
	ExecutableSHA256   string
}

func stableCLILeaseTerminal(id browserhost.CLITerminalIdentity) (cliLeaseTerminal, bool) {
	terminal := cliLeaseTerminal{
		UID:                id.UID,
		TTYDevice:          id.TTYDevice,
		SessionID:          id.SessionID,
		SessionLeaderStart: id.SessionLeaderStart,
		ExecutablePath:     id.ExecutablePath,
		ExecutableSHA256:   id.ExecutableSHA256,
	}
	return terminal, terminal.wellFormed()
}

// wellFormed reports whether a value could have come from a kernel attestation.
// It never accepts a placeholder identity, so a refused or fabricated lease is
// impossible by construction.
func (t cliLeaseTerminal) wellFormed() bool {
	if t.TTYDevice == 0 || t.SessionID == 0 || t.SessionLeaderStart == 0 {
		return false
	}
	if t.ExecutablePath == "" || len(t.ExecutablePath) > 4096 {
		return false
	}
	return cliV2CanonicalHex(t.ExecutableSHA256, 32)
}

func (t cliLeaseTerminal) equal(other cliLeaseTerminal) bool {
	if t.UID != other.UID || t.TTYDevice != other.TTYDevice || t.SessionID != other.SessionID ||
		t.SessionLeaderStart != other.SessionLeaderStart || t.ExecutablePath != other.ExecutablePath {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(t.ExecutableSHA256), []byte(other.ExecutableSHA256)) == 1
}

// cliLeaseKey is the exact public binding of one reusable command approval. It
// binds the live session pointer, its epoch and vault, the exact built-in spec
// identity and full spec image, every caller-visible command field, every target
// slot item id/revision/field, the stable terminal identity and the actual
// program image digest. It deliberately excludes the per-connection nonce, the
// temporary client root and the scope digest because those change on every run.
type cliLeaseKey struct {
	session       *personal.Session
	epoch         uint64
	vault         string
	specID        string
	specDigest    string
	specImage     string
	program       string
	argsDigest    string
	directory     string
	timeout       int
	helperDigest  string
	passDigest    string
	tokenEnv      string
	targets       string
	terminal      cliLeaseTerminal
	programSHA256 string
}

func (k cliLeaseKey) wellFormed() bool {
	if k.session == nil || k.vault == "" || len(k.vault) > 4096 || !filepath.IsAbs(k.vault) {
		return false
	}
	if k.specID == "" || len(k.specID) > 128 {
		return false
	}
	if !cliV2CanonicalHex(k.specDigest, 32) || !cliV2CanonicalHex(k.specImage, 32) ||
		!cliV2CanonicalHex(k.argsDigest, 32) || !cliV2CanonicalHex(k.helperDigest, 32) ||
		!cliV2CanonicalHex(k.passDigest, 32) || !cliV2CanonicalHex(k.targets, 32) ||
		!cliV2CanonicalHex(k.programSHA256, 32) {
		return false
	}
	if k.program == "" || len(k.program) > 4096 || !filepath.IsAbs(k.program) {
		return false
	}
	if k.directory == "" || len(k.directory) > 4096 || !filepath.IsAbs(k.directory) {
		return false
	}
	if k.timeout < 1 || k.timeout > 86400 {
		return false
	}
	if len(k.tokenEnv) > 128 {
		return false
	}
	return k.terminal.wellFormed()
}

func (k cliLeaseKey) equal(other cliLeaseKey) bool {
	if k.session != other.session || k.epoch != other.epoch || k.vault != other.vault ||
		k.specID != other.specID || k.program != other.program || k.directory != other.directory ||
		k.timeout != other.timeout || k.tokenEnv != other.tokenEnv {
		return false
	}
	if !k.terminal.equal(other.terminal) {
		return false
	}
	for _, pair := range [][2]string{
		{k.specDigest, other.specDigest}, {k.specImage, other.specImage},
		{k.argsDigest, other.argsDigest}, {k.helperDigest, other.helperDigest},
		{k.passDigest, other.passDigest}, {k.targets, other.targets},
		{k.programSHA256, other.programSHA256},
	} {
		if subtle.ConstantTimeCompare([]byte(pair[0]), []byte(pair[1])) != 1 {
			return false
		}
	}
	return true
}

// cliLeaseDigest hashes an ordered sequence of length-prefixed parts, so a
// shifted argument, a prefix of an argument list, a different helper ordering or
// a re-parented target can never hash to the same value.
func cliLeaseDigest(parts ...string) string {
	h := sha256.New()
	var size [8]byte
	for _, part := range parts {
		n := uint64(len(part))
		size[0] = byte(n >> 56)
		size[1] = byte(n >> 48)
		size[2] = byte(n >> 40)
		size[3] = byte(n >> 32)
		size[4] = byte(n >> 24)
		size[5] = byte(n >> 16)
		size[6] = byte(n >> 8)
		size[7] = byte(n)
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// cliLeaseKeyFor derives the exact key from one trusted scope, a stable terminal
// identity and the already-computed program image digest. It refuses anything
// that could not be an exact, complete owner scope.
func cliLeaseKeyFor(scope browserhost.CLIRunV2Scope, session *personal.Session, terminal cliLeaseTerminal, programSHA256 string) (cliLeaseKey, bool) {
	if session == nil {
		return cliLeaseKey{}, false
	}
	var zero cliLeaseKey
	if !validCLIRunV2Scope(scope) || !terminal.wellFormed() || !cliV2CanonicalHex(programSHA256, 32) {
		return zero, false
	}
	spec := cliV2SpecImage(scope.Request.Spec)
	if spec == "" {
		return zero, false
	}
	specImage := cliLeaseDigest("spec", spec)
	args := make([]string, 0, len(scope.Request.Args)+1)
	args = append(args, "args")
	args = append(args, scope.Request.Args...)
	helpers := make([]string, 0, len(scope.Request.HelperPath)+1)
	helpers = append(helpers, "helper-path")
	helpers = append(helpers, scope.Request.HelperPath...)
	// Passthrough is a map, so sort names first and length-prefix each pair.
	names := make([]string, 0, len(scope.Request.Passthrough))
	for name := range scope.Request.Passthrough {
		names = append(names, name)
	}
	sort.Strings(names)
	pass := make([]string, 0, len(names)*2+1)
	pass = append(pass, "passthrough")
	for _, name := range names {
		pass = append(pass, name, scope.Request.Passthrough[name])
	}
	// Targets are a set of exact item bindings; sort so wire ordering cannot
	// change the key while every id, revision and field stays bound.
	targets := append([]personal.BundleTarget(nil), scope.Targets...)
	sort.Slice(targets, func(i, j int) bool {
		a, b := targets[i], targets[j]
		if a.Slot != b.Slot {
			return a.Slot < b.Slot
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Revision != b.Revision {
			return a.Revision < b.Revision
		}
		return a.Field < b.Field
	})
	targetParts := make([]string, 0, len(targets)*4+1)
	targetParts = append(targetParts, "targets")
	for _, target := range targets {
		targetParts = append(targetParts, target.Slot, target.ID, target.Revision, target.Field)
	}
	key := cliLeaseKey{
		session:       session,
		epoch:         scope.Epoch,
		vault:         scope.VaultPath,
		specID:        scope.SpecID,
		specDigest:    scope.SpecDigest,
		specImage:     specImage,
		program:       scope.Request.Program,
		argsDigest:    cliLeaseDigest(args...),
		directory:     scope.Request.Directory,
		timeout:       scope.Request.TimeoutSeconds,
		helperDigest:  cliLeaseDigest(helpers...),
		passDigest:    cliLeaseDigest(pass...),
		tokenEnv:      scope.Request.TokenEnvName,
		targets:       cliLeaseDigest(targetParts...),
		terminal:      terminal,
		programSHA256: programSHA256,
	}
	return key, key.wellFormed()
}

// cliV2SpecImage is the canonical digest of the full trusted spec, so a spec
// whose id and digest somehow agree but whose slots, env, files, dirs or limits
// differ can never share a lease.
func cliV2SpecImage(spec cliprofile.Spec) string {
	raw, err := json.Marshal(cliprofile.CloneSpec(spec))
	if err != nil || len(raw) == 0 {
		return ""
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// cliLeaseEvidence is the public proof captured before an approval dialog or a
// lease lookup. exact still includes PeerStart for same-connection checks; the
// reusable key only uses terminal.
type cliLeaseEvidence struct {
	terminal      cliLeaseTerminal
	exact         browserhost.CLITerminalIdentity
	programSHA256 string
}

func captureCLILeaseEvidence(peer browserhost.Peer, program string) (cliLeaseEvidence, bool) {
	id, err := cliLeaseAttest(peer)
	if err != nil {
		return cliLeaseEvidence{}, false
	}
	terminal, ok := stableCLILeaseTerminal(id)
	if !ok {
		return cliLeaseEvidence{}, false
	}
	digest, err := cliLeaseHashProgram(program)
	if err != nil || !cliV2CanonicalHex(digest, 32) {
		return cliLeaseEvidence{}, false
	}
	return cliLeaseEvidence{terminal: terminal, exact: id, programSHA256: digest}, true
}

// cliLeaseApproval is the immutable proof and binding of one owner decision. It
// is built once, never mutated, and handed to browserhost as the final
// revalidation callbacks.
type cliLeaseApproval struct {
	peer  browserhost.Peer
	lease bool
	// dialog marks an approval that came from the native dialog. Such an
	// approval must still be the exact same peer process (including PeerStart)
	// after the owner decides. A lease reuse instead expects a fresh CLI process
	// and compares only the stable terminal identity.
	dialog        bool
	exact         browserhost.CLITerminalIdentity
	hasProof      bool
	program       string
	programSHA256 string
	deadline      time.Time
	key           cliLeaseKey
	cache         *cliLeaseCache
}

func (p *cliLeaseApproval) now() time.Time {
	if p != nil && p.cache != nil {
		return p.cache.nowTime()
	}
	return cliLeaseNow()
}

// revalidate re-reads the kernel proof after the owner decision and immediately
// before use. A dialog approval must still be the exact per-connection process
// (including PeerStart). A lease reuse expects a new CLI process, so it compares
// only the stable identity but still re-hashes the program image. It never
// touches a Session, so the broker may call it without any session mutex.
func (p *cliLeaseApproval) revalidate() error {
	if p == nil || !p.hasProof {
		return nil
	}
	if !p.deadline.IsZero() && !p.now().Before(p.deadline) {
		return errCLILeaseStale
	}
	if p.dialog {
		if !cliLeaseVerify(p.peer, p.exact) {
			return errCLILeaseStale
		}
	} else if p.lease {
		fresh, err := cliLeaseAttest(p.peer)
		if err != nil {
			return errCLILeaseStale
		}
		stable, ok := stableCLILeaseTerminal(fresh)
		if !ok || !stable.equal(p.key.terminal) {
			return errCLILeaseStale
		}
	}
	digest, err := cliLeaseHashProgram(p.program)
	if err != nil || subtle.ConstantTimeCompare([]byte(digest), []byte(p.programSHA256)) != 1 {
		return errCLILeaseStale
	}
	return nil
}

// stillValid is the cheap final check the broker makes immediately before the
// disclosure frame: absolute lease deadline, cache revocation, and nothing that
// would need the session mutex. The caller checks ctx separately.
func (p *cliLeaseApproval) stillValid() error {
	if p == nil {
		return nil
	}
	if !p.deadline.IsZero() && !p.now().Before(p.deadline) {
		return errCLILeaseStale
	}
	if p.lease {
		if _, ok := p.cache.match(p.key); !ok {
			return errCLILeaseStale
		}
	}
	return nil
}

// cliLeaseEntry is one resident lease. Only public metadata is stored here.
type cliLeaseEntry struct {
	key     cliLeaseKey
	expires time.Time
}

// cliLeaseCache is a bounded, in-memory authorization cache. The mutex is a
// leaf: no Session method or broker callback is ever called while it is held.
type cliLeaseCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries []cliLeaseEntry
}

func newCLILeaseCache() *cliLeaseCache {
	return &cliLeaseCache{now: time.Now}
}

func (c *cliLeaseCache) nowTime() time.Time {
	if c != nil && c.now != nil {
		return c.now()
	}
	return cliLeaseNow()
}

// pruneLocked drops expired entries before any capacity decision. It zeroes the
// dropped public metadata as well.
func (c *cliLeaseCache) pruneLocked(now time.Time) {
	kept := c.entries[:0]
	for _, entry := range c.entries {
		if now.Before(entry.expires) {
			kept = append(kept, entry)
		}
	}
	clear(c.entries[len(kept):])
	c.entries = kept
}

// add stores one explicit owner approval no later than the absolute cap. A
// duplicate exact key never extends the existing deadline. Expired entries are
// pruned before capacity is considered.
func (c *cliLeaseCache) add(key cliLeaseKey, deadline time.Time) error {
	if c == nil || !key.wellFormed() {
		return errCLILeaseStale
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowTime()
	c.pruneLocked(now)
	if cap := now.Add(cliLeaseTTL); deadline.After(cap) {
		deadline = cap
	}
	if !now.Before(deadline) {
		return errCLILeaseStale
	}
	for i := range c.entries {
		if c.entries[i].key.equal(key) {
			// An explicit second approval may not extend an existing lease: the
			// original absolute deadline is the only TTL that matters.
			return nil
		}
	}
	if len(c.entries) >= cliLeaseMax {
		return errCLILeaseFull
	}
	c.entries = append(c.entries, cliLeaseEntry{key: key, expires: deadline})
	return nil
}

// match reports the existing entry deadline for one exact, unexpired key. It
// never refreshes, extends or rewrites an entry.
func (c *cliLeaseCache) match(key cliLeaseKey) (time.Time, bool) {
	if c == nil || !key.wellFormed() {
		return time.Time{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowTime()
	c.pruneLocked(now)
	for _, entry := range c.entries {
		if entry.key.equal(key) && now.Before(entry.expires) {
			return entry.expires, true
		}
	}
	return time.Time{}, false
}

func (c *cliLeaseCache) purge() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
	c.entries = nil
}

func (c *cliLeaseCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(c.nowTime())
	return len(c.entries)
}

// hashCLIProgram hashes one ordinary executable program image with bounded IO
// and identity checks. The path itself must be a regular file (a symlink is
// refused by the initial Lstat), the opened descriptor must still be the same
// inode, and size/modtime may not change across the read. Nothing is written,
// executed or looked up on PATH.
func hashCLIProgram(path string) (string, error) {
	if path == "" || len(path) > 4096 || !filepath.IsAbs(path) {
		return "", errCLILeaseStale
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return "", errCLILeaseStale
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0o111 == 0 {
		return "", errCLILeaseStale
	}
	if before.Size() <= 0 || before.Size() > cliLeaseMaxProgramBytes {
		return "", errCLILeaseStale
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errCLILeaseStale
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return "", errCLILeaseStale
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, cliLeaseMaxProgramBytes+1))
	if err != nil || n != opened.Size() || n > cliLeaseMaxProgramBytes {
		return "", errCLILeaseStale
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) || after.Mode() != opened.Mode() {
		return "", errCLILeaseStale
	}
	cliHashProgramBeforeFinalLstat()
	// The descriptor proved which inode was read, but the path is what callers
	// name when they execute. Re-read it without following a final symlink and
	// require that it still names exactly the opened inode with the same mode,
	// size and modification time. An atomic rename after Open now fails closed
	// instead of returning the digest of a file the path no longer names.
	final, err := os.Lstat(path)
	if err != nil || !final.Mode().IsRegular() || final.Mode()&os.ModeSymlink != 0 {
		return "", errCLILeaseStale
	}
	if !os.SameFile(before, final) || !os.SameFile(opened, final) ||
		final.Mode() != opened.Mode() || final.Size() != opened.Size() ||
		!final.ModTime().Equal(opened.ModTime()) {
		return "", errCLILeaseStale
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
