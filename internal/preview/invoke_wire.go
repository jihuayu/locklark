package preview

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/gateway"
)

var errInvoke = errors.New("invocation invalid, not authorized, already used, or result unavailable")

const invokeDomain = "locklark/invoke-ticket/v1\x00"
const replyDomain = "locklark/invoke-reply/v1\x00"

type invocation struct {
	Purpose                                             string `json:"purpose,omitempty"`
	ID, Review, Session, Public, Audience, Reply, Nonce string
	Signature                                           []byte
}

func message(domain string, v any) []byte {
	b, _ := json.Marshal(v)
	return append([]byte(domain), b...)
}
func (t invocation) domain() string {
	if t.Purpose == statusPurpose {
		return "locklark/status-ticket/v1\x00"
	}
	return invokeDomain
}
func (t invocation) proof() []byte { t.Signature = nil; return message(t.domain(), t) }
func (t invocation) digest() string {
	h := sha256.Sum256(message(t.domain(), t))
	return hex.EncodeToString(h[:])
}
func hexSize(s string, n int) bool {
	if len(s) != 2*n {
		return false
	}
	raw, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(raw) == s
}
func readPath(path string, n int64) ([]byte, error) {
	return read(filepath.Dir(path), filepath.Base(path), n)
}
func sealJSON(r age.Recipient, v any) ([]byte, error) {
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return nil, err
	}
	if err = json.NewEncoder(w).Encode(v); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func unsealJSON(id age.Identity, raw []byte, n int64, v any) error {
	r, err := age.Decrypt(bytes.NewReader(raw), id)
	if err != nil {
		return errInvoke
	}
	data, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil || int64(len(data)) > n || json.Unmarshal(data, v) != nil {
		return errInvoke
	}
	return nil
}

type localAttempt struct {
	Key    string
	Ticket invocation
	Host   []byte
}

func PrepareInvocation(dir, keyFile, recipientFile, hostKeyFile, session, id, review string) error {
	return prepareEnvelope(dir, keyFile, recipientFile, hostKeyFile, session, id, review, "", "")
}
func prepareEnvelope(dir, keyFile, recipientFile, hostKeyFile, session, id, review, purpose, challenge string) error {
	if !validSession(session) || !validID(id) || !hexSize(review, 32) {
		return errInvoke
	}
	seed, err := readPath(keyFile, 32)
	if err != nil {
		return err
	}
	defer clear(seed)
	if len(seed) != 32 {
		return errInvoke
	}
	signer := ed25519.NewKeyFromSeed(seed)
	defer clear(signer)
	pub, err := readPath(recipientFile, 256)
	if err != nil {
		return err
	}
	recipient, err := age.ParseX25519Recipient(string(bytes.TrimSpace(pub)))
	if err != nil {
		return errInvoke
	}
	host, err := readPath(hostKeyFile, 32)
	if err != nil {
		return err
	}
	if !validPublic(hex.EncodeToString(host)) {
		return errInvoke
	}
	reply, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	t := invocation{ID: id, Review: review, Session: session, Public: hex.EncodeToString(signer[32:]), Audience: recipient.String(), Reply: reply.Recipient().String(), Nonce: hex.EncodeToString(nonce[:])}
	if purpose == statusPurpose {
		t.Purpose = purpose
		t.Nonce = challenge
	}
	t.Signature = ed25519.Sign(signer, t.proof())
	encrypted, err := sealJSON(recipient, t)
	if err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err = writeJSON(dir, "attempt.private", localAttempt{reply.String(), t, host}); err != nil {
		return err
	}
	if purpose == statusPurpose {
		return write(dir, "query.age", encrypted)
	}
	return write(dir, "invocation.age", encrypted)
}
func readTicket(path string, id *age.X25519Identity) (invocation, error) {
	return readEnvelope(path, id, "")
}
func readEnvelope(path string, id *age.X25519Identity, purpose string) (invocation, error) {
	var t invocation
	b, err := readPath(path, 8192)
	if err != nil {
		return t, err
	}
	if unsealJSON(id, b, 4096, &t) != nil || !validID(t.ID) || !hexSize(t.Review, 32) || !validSession(t.Session) || !validID(t.Nonce) || t.Audience != id.Recipient().String() || !validPublic(t.Public) {
		return invocation{}, errInvoke
	}
	r, err := age.ParseX25519Recipient(t.Reply)
	pub, _ := hex.DecodeString(t.Public)
	if err != nil || r.String() != t.Reply || t.Purpose != purpose || !ed25519.Verify(pub, t.proof(), t.Signature) {
		return invocation{}, errInvoke
	}
	// Parsing an age recipient checks its encoding, but not low-order points.
	if _, err := r.Wrap(make([]byte, 16)); err != nil {
		return invocation{}, errInvoke
	}
	return t, nil
}

type FieldMetadata struct {
	Epoch uint64 `json:"epoch"`
	Field string `json:"field"`
	Kind  string `json:"kind"`
}

func inspectMetadata(raw []byte) (FieldMetadata, error) {
	z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return FieldMetadata{}, errInvoke
	}
	f, err := z.Open("export.data")
	if err != nil {
		return FieldMetadata{}, errInvoke
	}
	defer f.Close()
	var data struct {
		Accounts []struct {
			Vaults []struct {
				Attrs struct{ UUID string }
				Items []struct {
					UUID    string
					Details struct {
						Sections []struct {
							Name   string
							Fields []struct {
								ID    string
								Value map[string]json.RawMessage
							}
						}
					}
				}
			}
		}
	}
	if json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&data) != nil {
		return FieldMetadata{}, errInvoke
	}
	for _, a := range data.Accounts {
		for _, v := range a.Vaults {
			if v.Attrs.UUID != "synthetic-vault" {
				continue
			}
			for _, item := range v.Items {
				if item.UUID != "login-sample" {
					continue
				}
				for _, s := range item.Details.Sections {
					if s.Name != "ops" {
						continue
					}
					for _, field := range s.Fields {
						if field.ID == "otp-demo" && field.Value["totp"] != nil {
							return FieldMetadata{3, field.ID, "totp"}, nil
						}
					}
				}
			}
		}
	}
	return FieldMetadata{}, errInvoke
}

type RecordedResult struct {
	Source string             `json:"source"`
	Pull   gateway.PullResult `json:"pull"`
}
type signedReply struct {
	Pull     *RecordedResult `json:"pull,omitempty"`
	Ticket   string
	Metadata FieldMetadata
	Sig      []byte
}

func (r signedReply) proof() []byte { r.Sig = nil; return message(replyDomain, r) }
func OpenInvocationResult(dir, path string) (FieldMetadata, error) {
	r, e := openReply(dir, path)
	if e != nil {
		return FieldMetadata{}, e
	}
	if r.Pull != nil {
		return FieldMetadata{}, errInvoke
	}
	return r.Metadata, nil
}
func InvocationResult(dir, path string) (any, error) {
	r, e := openReply(dir, path)
	if e != nil {
		return nil, e
	}
	if r.Pull != nil {
		return *r.Pull, nil
	}
	return r.Metadata, nil
}
func openReply(dir, path string) (signedReply, error) {
	local, err := read(dir, "attempt.private", 8192)
	if err != nil {
		return signedReply{}, err
	}
	var state localAttempt
	if json.Unmarshal(local, &state) != nil || len(state.Host) != 32 {
		return signedReply{}, errInvoke
	}
	id, err := age.ParseX25519Identity(state.Key)
	if err != nil || id.Recipient().String() != state.Ticket.Reply {
		return signedReply{}, errInvoke
	}
	ciphertext, err := readPath(path, 8192)
	if err != nil {
		return signedReply{}, err
	}
	var reply signedReply
	if unsealJSON(id, ciphertext, 4096, &reply) != nil || reply.Ticket != state.Ticket.digest() || !ed25519.Verify(state.Host, reply.proof(), reply.Sig) {
		return signedReply{}, errInvoke
	}
	return reply, nil
}
