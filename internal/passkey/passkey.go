// Package passkey implements the ES256 software authenticator used by the
// native vault. The caller supplies a browser-authenticated origin and explicit
// user presence/verification; requests never choose their own signing origin.
package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/origin"
	"golang.org/x/net/publicsuffix"
)

var ErrRefused = errors.New("passkey request refused")
var ErrUnsupported = errors.New("passkey options unsupported; use another authenticator")
var ErrExcluded = errors.New("passkey already registered")
var b64 = base64.RawURLEncoding

const MaxOptions = 32 << 10

type Descriptor struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}
type Options struct {
	Challenge string `json:"challenge"`
	RP        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rp"`
	RPID string `json:"rpId"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	Parameters []struct {
		Type string `json:"type"`
		Alg  int    `json:"alg"`
	} `json:"pubKeyCredParams"`
	Exclude   []Descriptor `json:"excludeCredentials"`
	Allow     []Descriptor `json:"allowCredentials"`
	Selection struct {
		Attachment         string `json:"authenticatorAttachment"`
		ResidentKey        string `json:"residentKey"`
		RequireResidentKey bool   `json:"requireResidentKey"`
		Verification       string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	Verification string                     `json:"userVerification"`
	Attestation  string                     `json:"attestation"`
	Timeout      float64                    `json:"timeout"`
	Extensions   map[string]json.RawMessage `json:"extensions"`
	Hints        []string                   `json:"hints"`
}

type Request struct {
	Create       bool
	Origin, RPID string
	Options      Options
}

// Record is secret storage, never a browser DTO. One login owns one credential.
type Record struct {
	Version     int    `json:"version"`
	ID          string `json:"id"`
	RPID        string `json:"rp_id"`
	UserID      string `json:"user_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	PrivateKey  []byte `json:"private_key"`
}

func (*Record) String() string   { return "[private passkey]" }
func (*Record) GoString() string { return "[private passkey]" }
func (r *Record) Clear() {
	if r != nil {
		clear(r.PrivateKey)
		r.PrivateKey = nil
	}
}

type Response struct {
	ID         string                `json:"id"`
	RawID      string                `json:"rawId"`
	Type       string                `json:"type"`
	Attachment string                `json:"authenticatorAttachment"`
	Response   AuthenticatorResponse `json:"response"`
	Extensions map[string]any        `json:"clientExtensionResults"`
}
type AuthenticatorResponse struct {
	ClientDataJSON     string   `json:"clientDataJSON"`
	AttestationObject  string   `json:"attestationObject,omitempty"`
	AuthenticatorData  string   `json:"authenticatorData"`
	Signature          string   `json:"signature,omitempty"`
	UserHandle         string   `json:"userHandle,omitempty"`
	PublicKey          string   `json:"publicKey,omitempty"`
	PublicKeyAlgorithm int      `json:"publicKeyAlgorithm,omitempty"`
	Transports         []string `json:"transports,omitempty"`
}

func (Response) String() string   { return "[passkey response]" }
func (Response) GoString() string { return "[passkey response]" }
func decode(s string, min, max int) ([]byte, bool) {
	b, e := b64.Strict().DecodeString(s)
	return b, e == nil && len(b) >= min && len(b) <= max && b64.EncodeToString(b) == s
}
func textOK(s string) bool {
	return len(s) <= 1024 && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func ValidRP(source, rp string) bool {
	normalized, e := origin.Parse(source)
	if e != nil || normalized != source {
		return false
	}
	u, _ := url.Parse(source)
	if rp == "" || rp != strings.ToLower(rp) || len(rp) > 253 {
		return false
	}
	if _, e = origin.Parse("https://" + rp); e != nil {
		return false
	}
	if u.Hostname() != rp && !strings.HasSuffix(u.Hostname(), "."+rp) {
		return false
	}
	// Include private suffixes (e.g. github.io); a tenant cannot claim its siblings.
	suffix, _ := publicsuffix.PublicSuffix(rp)
	return suffix != rp
}
func Parse(source string, create bool, raw []byte) (*Request, error) {
	if len(raw) == 0 || len(raw) > MaxOptions || !strictUnicode(raw) {
		return nil, ErrRefused
	}
	// Reject duplicate keys at every depth before struct decoding.
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 12 {
			return ErrRefused
		}
		tok, e := dec.Token()
		if e != nil {
			return e
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				k, e := dec.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[strings.ToLower(s)] {
					return ErrRefused
				}
				seen[strings.ToLower(s)] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			_, e = dec.Token()
			return e
		case json.Delim('['):
			for dec.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			_, e = dec.Token()
			return e
		}
		return nil
	}
	if walk(0) != nil {
		return nil, ErrRefused
	}
	if _, e := dec.Token(); e != io.EOF {
		return nil, ErrRefused
	}
	var o Options
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&o) != nil {
		return nil, ErrUnsupported
	}
	if _, ok := decode(o.Challenge, 16, 1024); !ok {
		return nil, ErrRefused
	}
	if o.Timeout < 0 || o.Timeout > 600000 || len(o.Allow) > 64 || len(o.Exclude) > 64 || len(o.Parameters) > 32 {
		return nil, ErrRefused
	}
	rp := o.RPID
	if create {
		rp = o.RP.ID
	}
	if rp == "" {
		u, e := url.Parse(source)
		if e != nil {
			return nil, ErrRefused
		}
		rp = u.Hostname()
	}
	if !ValidRP(source, rp) {
		return nil, ErrRefused
	}
	uv := o.Verification
	if create {
		uv = o.Selection.Verification
	}
	if uv != "" && uv != "required" && uv != "preferred" && uv != "discouraged" {
		return nil, ErrRefused
	}
	for _, list := range [][]Descriptor{o.Allow, o.Exclude} {
		for _, d := range list {
			if d.Type != "public-key" {
				return nil, ErrUnsupported
			}
			if _, ok := decode(d.ID, 1, 1024); !ok {
				return nil, ErrRefused
			}
		}
	}
	for key, value := range o.Extensions {
		switch key {
		case "credProps":
			var v bool
			if json.Unmarshal(value, &v) != nil {
				return nil, ErrRefused
			}
		default:
			return nil, ErrUnsupported // Never silently claim PRF/largeBlob/AppID support.
		}
	}
	if create {
		if _, ok := decode(o.User.ID, 1, 64); !ok || o.User.Name == "" || !textOK(o.User.Name) || !textOK(o.User.DisplayName) || !textOK(o.RP.Name) {
			return nil, ErrRefused
		}
		if o.Selection.ResidentKey != "" && o.Selection.ResidentKey != "required" && o.Selection.ResidentKey != "preferred" && o.Selection.ResidentKey != "discouraged" {
			return nil, ErrRefused
		}
		if o.Selection.Attachment != "" && o.Selection.Attachment != "platform" && o.Selection.Attachment != "cross-platform" {
			return nil, ErrRefused
		}
		if o.Selection.Attachment == "cross-platform" {
			return nil, ErrUnsupported
		}
		if o.Attestation != "" && o.Attestation != "none" && o.Attestation != "indirect" && o.Attestation != "direct" {
			return nil, ErrUnsupported
		}
		supported := false
		for _, p := range o.Parameters {
			if p.Type == "public-key" && p.Alg == -7 {
				supported = true
			}
		}
		if !supported {
			return nil, ErrUnsupported
		}
	}
	return &Request{create, source, rp, o}, nil
}
func (r *Request) RequiresVerification() bool {
	if r.Create {
		return r.Options.Selection.Verification == "required"
	}
	return r.Options.Verification == "required"
}
func Load(raw []byte) (*Record, error) {
	if len(raw) == 0 || len(raw) > 8192 || !strictUnicode(raw) {
		return nil, ErrRefused
	}
	var r Record
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil {
		r.Clear()
		return nil, ErrRefused
	}
	if dec.Decode(new(any)) != io.EOF {
		r.Clear()
		return nil, ErrRefused
	}
	k, e := x509.ParsePKCS8PrivateKey(r.PrivateKey)
	ec, ok := k.(*ecdsa.PrivateKey)
	_, idOK := decode(r.ID, 32, 32)
	_, userOK := decode(r.UserID, 1, 64)
	if e != nil || !ok || ec.Curve != elliptic.P256() || r.Version != 1 || !idOK || !userOK || !ValidRP("https://"+r.RPID, r.RPID) || !textOK(r.Name) || !textOK(r.DisplayName) {
		r.Clear()
		return nil, ErrRefused
	}
	return &r, nil
}
func ValidRecord(raw []byte) bool {
	r, e := Load(raw)
	if r != nil {
		r.Clear()
	}
	return e == nil
}
func (r *Request) Matches(c *Record) bool {
	if r == nil || c == nil || r.Create || r.RPID != c.RPID {
		return false
	}
	if len(r.Options.Allow) == 0 {
		return true
	}
	for _, d := range r.Options.Allow {
		if d.ID == c.ID {
			return true
		}
	}
	return false
}
func (r *Request) Excludes(c *Record) bool {
	if c == nil || c.RPID != r.RPID {
		return false
	}
	for _, d := range r.Options.Exclude {
		if d.ID == c.ID {
			return true
		}
	}
	return false
}

// CBOR below encodes only the fixed WebAuthn/COSE maps, text and byte strings.
// No untrusted CBOR is decoded, and integer lengths are bounded by Parse.
func head(major byte, n uint64) []byte {
	if n < 24 {
		return []byte{major<<5 | byte(n)}
	}
	if n <= 255 {
		return []byte{major<<5 | 24, byte(n)}
	}
	if n <= 65535 {
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
	return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}
func cbytes(b []byte) []byte { return append(head(2, uint64(len(b))), b...) }
func ctext(s string) []byte  { return append(head(3, uint64(len(s))), s...) }
func publicCOSE(k *ecdsa.PublicKey) []byte {
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21}
	out = append(out, cbytes(k.X.FillBytes(make([]byte, 32)))...)
	out = append(out, 0x22)
	return append(out, cbytes(k.Y.FillBytes(make([]byte, 32)))...)
}
func data(r *Request, verified bool) ([]byte, []byte) {
	kind := "webauthn.get"
	if r.Create {
		kind = "webauthn.create"
	}
	client, _ := json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{kind, r.Options.Challenge, r.Origin, false})
	hash := sha256.Sum256([]byte(r.RPID))
	auth := append([]byte{}, hash[:]...)
	flags := byte(0x01 | 0x08) // UP; backup eligible. BS remains false until a backup is known.
	if verified {
		flags |= 0x04
	}
	if r.Create {
		flags |= 0x40
	}
	auth = append(auth, flags, 0, 0, 0, 0) // Multi-device credentials use a zero signature counter.
	return client, auth
}
func Create(r *Request, verified bool) ([]byte, Response, error) {
	if r == nil || !r.Create || r.RequiresVerification() && !verified {
		return nil, Response{}, ErrRefused
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, Response{}, ErrRefused
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, Response{}, ErrRefused
	}
	defer clear(private)
	id := make([]byte, 32)
	if _, e = rand.Read(id); e != nil {
		return nil, Response{}, ErrRefused
	}
	record := Record{1, b64.EncodeToString(id), r.RPID, r.Options.User.ID, r.Options.User.Name, r.Options.User.DisplayName, private}
	raw, e := json.Marshal(record)
	if e != nil {
		return nil, Response{}, ErrRefused
	}
	client, auth := data(r, verified)
	auth = append(auth, make([]byte, 16)...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(id)))
	auth = append(auth, id...)
	auth = append(auth, publicCOSE(&key.PublicKey)...)
	att := []byte{0xa3}
	att = append(att, ctext("fmt")...)
	att = append(att, ctext("none")...)
	att = append(att, ctext("attStmt")...)
	att = append(att, 0xa0)
	att = append(att, ctext("authData")...)
	att = append(att, cbytes(auth)...)
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	extensions := map[string]any{}
	if string(r.Options.Extensions["credProps"]) == "true" {
		extensions["credProps"] = map[string]bool{"rk": true}
	}
	response := Response{record.ID, record.ID, "public-key", "platform", AuthenticatorResponse{ClientDataJSON: b64.EncodeToString(client), AttestationObject: b64.EncodeToString(att), AuthenticatorData: b64.EncodeToString(auth), PublicKey: b64.EncodeToString(public), PublicKeyAlgorithm: -7, Transports: []string{"internal"}}, extensions}
	return raw, response, nil
}
func Get(r *Request, c *Record, verified bool) (Response, error) {
	if !r.Matches(c) || r.RequiresVerification() && !verified {
		return Response{}, ErrRefused
	}
	private, e := x509.ParsePKCS8PrivateKey(c.PrivateKey)
	if e != nil {
		return Response{}, ErrRefused
	}
	key, ok := private.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return Response{}, ErrRefused
	}
	client, auth := data(r, verified)
	hash := sha256.Sum256(client)
	signed := append(append([]byte{}, auth...), hash[:]...)
	digest := sha256.Sum256(signed)
	signature, e := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if e != nil {
		return Response{}, ErrRefused
	}
	return Response{c.ID, c.ID, "public-key", "platform", AuthenticatorResponse{ClientDataJSON: b64.EncodeToString(client), AuthenticatorData: b64.EncodeToString(auth), Signature: b64.EncodeToString(signature), UserHandle: c.UserID}, map[string]any{}}, nil
}

func strictUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for n := 0; n < len(raw); n++ {
		if raw[n] != '"' {
			continue
		}
		n++
		for ; n < len(raw) && raw[n] != '"'; n++ {
			if raw[n] != '\\' {
				continue
			}
			n++
			if n >= len(raw) {
				return false
			}
			if raw[n] != 'u' {
				continue
			}
			if n+4 >= len(raw) {
				return false
			}
			v, e := strconv.ParseUint(string(raw[n+1:n+5]), 16, 16)
			if e != nil {
				return false
			}
			n += 4
			if v >= 0xdc00 && v <= 0xdfff {
				return false
			}
			if v >= 0xd800 && v <= 0xdbff {
				if n+6 >= len(raw) || raw[n+1] != '\\' || raw[n+2] != 'u' {
					return false
				}
				w, e := strconv.ParseUint(string(raw[n+3:n+7]), 16, 16)
				if e != nil || w < 0xdc00 || w > 0xdfff {
					return false
				}
				n += 6
			}
		}
	}
	return true
}
