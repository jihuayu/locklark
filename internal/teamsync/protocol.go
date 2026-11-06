// Package teamsync transports verified team ciphertext through a fixed trusted
// sequencer. It does not accept plaintext items or device/owner private keys on
// the server. Fresh reads are observations, never leases authorizing a write.
package teamsync

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/vault"
)

var (
	ErrInvalid   = errors.New("invalid team sync input or proof")
	ErrDenied    = errors.New("team sync authorization refused")
	ErrConflict  = errors.New("team sync parent changed; explicit review required")
	ErrCapacity  = errors.New("team sync capacity exceeded")
	ErrTransport = errors.New("team sync transport failed")
	ErrFreshness = errors.New("team sync observation expired")
	ErrAnchor    = errors.New("team sync checkpoint storage failed")
	ErrUnknown   = errors.New("team publication outcome unknown; reconcile before another publication")
	ErrClosed    = errors.New("team sync client closed")
)

const (
	protocol         = "locklark.team-sync/v1"
	ReadPath         = "/v1/team-sync/read"
	PublishPath      = "/v1/team-sync/publish"
	MaxReadBytes     = 8 << 10
	MaxPublishBytes  = 16 << 20
	MaxResponseBytes = 32 << 20
)

type signedRefusal struct{ err error }

func (e *signedRefusal) Error() string { return e.err.Error() }
func (e *signedRefusal) Unwrap() error { return e.err }

type publication struct {
	Proposal directory.Proposal `json:"proposal"`
	Snapshot vault.Snapshot     `json:"snapshot"`
}
type requestProof struct {
	Protocol   string               `json:"protocol"`
	Scope      string               `json:"scope"`
	Action     string               `json:"action"`
	Kind       string               `json:"auth_kind"`
	ID         string               `json:"id"`
	Nonce      string               `json:"nonce"`
	Anchor     directory.Checkpoint `json:"anchor"`
	BodyDigest string               `json:"body_digest"`
	Signature  []byte               `json:"signature"`
}
type request struct {
	Proof       requestProof `json:"request"`
	Publication *publication `json:"publication,omitempty"`
}
type response struct {
	Protocol      string               `json:"protocol"`
	RequestDigest string               `json:"request_digest"`
	Nonce         string               `json:"nonce"`
	Status        string               `json:"status"`
	Head          directory.Checkpoint `json:"head"`
	HistoryDigest string               `json:"history_digest"`
	ReceiptDigest string               `json:"receipt_digest"`
	History       *directory.History   `json:"history,omitempty"`
	Receipt       *directory.Receipt   `json:"receipt,omitempty"`
	Signature     []byte               `json:"signature"`
}

func encode(v any) []byte { raw, _ := json.Marshal(v); return raw }
func digest(domain string, v any) string {
	h := sha256.New()
	h.Write([]byte("locklark/team-sync/" + domain + "/v1\x00"))
	h.Write(encode(v))
	return hex.EncodeToString(h.Sum(nil))
}
func (p requestProof) signingBytes() []byte {
	p.Signature = nil
	return append([]byte("locklark/team-sync/request/v1\x00"), encode(p)...)
}
func (r response) signingBytes() []byte {
	return append([]byte("locklark/team-sync/response/v1\x00"), encode(struct {
		Protocol, RequestDigest, Nonce, Status string
		Head                                   directory.Checkpoint
		HistoryDigest, ReceiptDigest           string
	}{r.Protocol, r.RequestDigest, r.Nonce, r.Status, r.Head, r.HistoryDigest, r.ReceiptDigest})...)
}
func canonicalHex(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	raw, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(raw) == s
}
func validPrivate(key ed25519.PrivateKey) bool {
	if len(key) != ed25519.PrivateKeySize {
		return false
	}
	expected := ed25519.NewKeyFromSeed(key[:32])
	defer clear(expected)
	return bytes.Equal(expected, key)
}
func (r request) valid(c *directory.Config, action string) bool {
	p := r.Proof
	if p.Protocol != protocol || p.Scope != c.Genesis().Scope || p.Action != action || !c.ValidCheckpoint(p.Anchor) || !canonicalHex(p.Nonce, 32) || !canonicalHex(p.BodyDigest, 32) || len(p.Signature) != 64 {
		return false
	}
	if p.Kind == "owner" {
		if !canonicalHex(p.ID, 32) {
			return false
		}
	} else if p.Kind == "device" {
		if !canonicalHex(p.ID, 16) {
			return false
		}
	} else {
		return false
	}
	if (r.Publication != nil) != (action == "publish") {
		return false
	}
	return p.BodyDigest == digest("payload", r.Publication)
}

// Token bounds precede struct decoding to limit unknown/deep/huge-array inputs
// before they can amplify a bounded network body into unbounded Go allocations.
func decode(raw []byte, v any) error {
	if !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if depth > 32 || nodes > 2_000_000 {
			return ErrCapacity
		}
		t, e := d.Token()
		if e != nil {
			return ErrInvalid
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				key, ok := k.(string)
				if e != nil || !ok || len(key) > 64 || seen[key] || len(seen) >= 32 {
					return ErrInvalid
				}
				seen[key] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			if t, e = d.Token(); e != nil || t != json.Delim('}') {
				return ErrInvalid
			}
		case json.Delim('['):
			count := 0
			for d.More() {
				count++
				if count > 1024 {
					return ErrCapacity
				}
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			if t, e = d.Token(); e != nil || t != json.Delim(']') {
				return ErrInvalid
			}
		case json.Delim('}'), json.Delim(']'):
			return ErrInvalid
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || !bytes.Equal(raw, encode(v)) {
		return ErrInvalid
	}
	return nil
}

func cloneHistory(h directory.History) directory.History {
	var out directory.History
	_ = json.Unmarshal(encode(h), &out)
	return out
}
func cloneView(v directory.View) directory.View {
	var out directory.View
	_ = json.Unmarshal(encode(v), &out)
	return out
}
