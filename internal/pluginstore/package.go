// Package pluginstore verifies and stores offline, publisher-signed bundles.
// It never executes a package, fetches dependencies or grants tool permissions.
package pluginstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"unicode/utf8"

	"filippo.io/edwards25519"
)

var ErrInvalid = errors.New("invalid plugin package, pin, checkpoint or catalog")
var ErrConflict = errors.New("plugin catalog changed; read current state before retrying")
var ErrVersion = errors.New("plugin version must increase")
var ErrRevoked = errors.New("plugin ID is permanently revoked in this catalog")
var ErrPublisher = errors.New("plugin publisher cannot change")
var ErrNotFound = errors.New("plugin is not installed")
var ErrStorage = errors.New("plugin catalog storage failed; operation may be committed")
var ErrExists = errors.New("plugin catalog already exists")
var ErrCapacity = errors.New("plugin catalog capacity reached")

const MaxPackage = 2 << 20
const maxPlugins = 32
const maxEvents = 4096

// Pins must be supplied from trusted local operator configuration independently
// of the catalog and package. Keep pins for revoked IDs to verify their evidence.
type Pins map[string]string

func copyPins(pins Pins) (Pins, error) {
	if pins == nil || len(pins) > maxPlugins {
		return nil, ErrInvalid
	}
	out := Pins{}
	for id, publisher := range pins {
		if !ValidID(id) {
			return nil, ErrInvalid
		}
		if _, e := publicKey(publisher); e != nil {
			return nil, ErrInvalid
		}
		out[id] = publisher
	}
	return out, nil
}

type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}
type Release struct {
	Schema       int          `json:"schema"`
	ID           string       `json:"id"`
	Version      uint64       `json:"version"`
	Publisher    string       `json:"publisher"`
	Runtime      string       `json:"runtime"`
	Capabilities []string     `json:"capabilities"`
	Dependencies []Dependency `json:"dependencies"`
	Bundle       []byte       `json:"bundle"`
	Signature    []byte       `json:"signature"`
}

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}/[a-z][a-z0-9-]{0,47}$`)
var depPattern = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]{0,47}/)?[a-z0-9][a-z0-9._-]{0,63}$`)
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

func ValidID(id string) bool {
	return len(id) <= 113 && idPattern.MatchString(id) && !bytes.HasPrefix([]byte(id), []byte("locklark.builtin/"))
}
func hexValue(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}
func publicKey(s string) (ed25519.PublicKey, error) {
	if !hexValue(s, 32) {
		return nil, ErrInvalid
	}
	raw, _ := hex.DecodeString(s)
	p, e := new(edwards25519.Point).SetBytes(raw)
	if e != nil || !bytes.Equal(p.Bytes(), raw) || new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, ErrInvalid
	}
	return ed25519.PublicKey(raw), nil
}
func encoded(v any) []byte { b, _ := json.Marshal(v); return b }
func Digest(raw []byte) string {
	h := sha256.Sum256(append([]byte("locklark/plugin-package/digest/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}
func (p Release) proof() []byte {
	p.Signature = nil
	return append([]byte("locklark/plugin-package/signature/v1\x00"), encoded(p)...)
}
func (p Release) shape() bool {
	if p.Schema != 1 || !ValidID(p.ID) || p.Version == 0 || p.Version > 1_000_000_000 || p.Runtime != "bun-1.4.4/bundled-v1" || len(p.Bundle) == 0 || len(p.Bundle) > 1<<20 || !utf8.Valid(p.Bundle) || bytes.IndexByte(p.Bundle, 0) >= 0 || len(p.Capabilities) != 1 || p.Capabilities[0] != "github.pulls.get" || p.Dependencies == nil || len(p.Dependencies) > 64 {
		return false
	}
	if _, e := publicKey(p.Publisher); e != nil {
		return false
	}
	previous := ""
	for _, d := range p.Dependencies {
		if len(d.Name) > 113 || !depPattern.MatchString(d.Name) || d.Name <= previous || len(d.Version) > 64 || !versionPattern.MatchString(d.Version) || !hexValue(d.SHA256, 32) {
			return false
		}
		previous = d.Name
	}
	return true
}

// Sign is a publisher build helper. Dependency hashes are signed provenance
// assertions; the catalog cannot prove a reproducible build from bundled JS.
func Sign(p Release, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	canonical := ed25519.NewKeyFromSeed(key[:32])
	defer clear(canonical)
	if !bytes.Equal(key, canonical) {
		return nil, ErrInvalid
	}
	p.Publisher = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if !p.shape() {
		return nil, ErrInvalid
	}
	p.Signature = ed25519.Sign(key, p.proof())
	raw := encoded(p)
	if len(raw) > MaxPackage {
		return nil, ErrInvalid
	}
	return raw, nil
}

// Verify uses independently supplied identity and publisher pins, never a key
// learned from the package itself. Canonical encoding rejects duplicate fields,
// unknown fields, alternate casing, trailing data and noncanonical numbers.
func Verify(raw []byte, id, publisher string) (Release, error) {
	p, _, e := verifyDigest(raw, id, publisher)
	return p, e
}

// verifyDigest returns the verified release and the SHA-256 digest of the exact
// signed bytes it decoded, so callers need not hash the bundle twice.
func verifyDigest(raw []byte, id, publisher string) (Release, string, error) {
	if len(raw) == 0 || len(raw) > MaxPackage || !ValidID(id) {
		return Release{}, "", ErrInvalid
	}
	key, e := publicKey(publisher)
	if e != nil {
		return Release{}, "", ErrInvalid
	}
	var p Release
	if json.Unmarshal(raw, &p) != nil || !p.shape() || p.ID != id || p.Publisher != publisher || len(p.Signature) != 64 || !bytes.Equal(raw, encoded(p)) || !ed25519.Verify(key, p.proof(), p.Signature) {
		return Release{}, "", ErrInvalid
	}
	return p, Digest(raw), nil
}
