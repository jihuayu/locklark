package directory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"

	"filippo.io/age"
)

// Enrollment is the exact identity shown and approved by the receiving device.
// It proves key possession, not a role grant or authorization to publish data.
type Enrollment struct {
	Parent Checkpoint `json:"parent"`
	Member string     `json:"member"`
	Device Device     `json:"device"`
}
type Challenge struct {
	Enrollment  Enrollment `json:"enrollment"`
	NonceDigest string     `json:"nonce_digest"`
	Ciphertext  []byte     `json:"ciphertext"`
	Owner       string     `json:"owner"`
	Signature   []byte     `json:"signature"`
}
type Admission struct {
	Challenge Challenge `json:"challenge"`
	Nonce     []byte    `json:"nonce"`
	Signature []byte    `json:"signature"`
}

// NewConfigWithPossession pins a distinct, mandatory-possession policy into the
// trust scope. Legacy NewConfig stores owner assertions only; it cannot read or
// write this scope, so dropping the policy is not a compatible downgrade.
func NewConfigWithPossession(pins Pins) (*Config, error) {
	c, err := NewConfig(pins)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(append([]byte("locklark/team-directory/possession-required/v1\x00"), []byte(c.scope)...))
	c.scope = hex.EncodeToString(h[:])
	c.requirePossession = true
	return c, nil
}
func (c *Config) validEnrollment(e Enrollment) bool {
	if !c.valid() || !c.requirePossession || !c.validCheckpoint(e.Parent) || e.Parent.Version >= maxVersions {
		return false
	}
	_, err := c.roster([]Member{{ID: e.Member, Role: "reader", Devices: []Device{e.Device}}}, false)
	return err == nil
}
func (c Challenge) proof() []byte {
	c.Signature = nil
	return append([]byte("locklark/team-device/challenge/v1\x00"), encoded(c)...)
}
func (p Admission) proof() []byte {
	p.Signature = nil
	return append([]byte("locklark/team-device/response/v1\x00"), encoded(p)...)
}

// The trusted owner chooses a fresh unpredictable nonce and encrypts it to the
// advertised age recipient. Only public challenge material is returned.
func IssueChallenge(c *Config, owner ed25519.PrivateKey, enrollment Enrollment) (Challenge, error) {
	who, err := c.owner(owner)
	if err != nil || !c.validEnrollment(enrollment) {
		return Challenge{}, ErrInvalid
	}
	recipient, err := age.ParseX25519Recipient(enrollment.Device.Encryption)
	if err != nil {
		return Challenge{}, ErrInvalid
	}
	nonce := make([]byte, 32)
	defer clear(nonce)
	if _, err = rand.Read(nonce); err != nil {
		return Challenge{}, ErrInvalid
	}
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return Challenge{}, ErrInvalid
	}
	if _, err = writer.Write(nonce); err != nil {
		return Challenge{}, ErrInvalid
	}
	if err = writer.Close(); err != nil {
		return Challenge{}, ErrInvalid
	}
	h := sha256.Sum256(nonce)
	out := Challenge{Enrollment: enrollment, NonceDigest: hex.EncodeToString(h[:]), Ciphertext: ciphertext.Bytes(), Owner: who}
	out.Signature = ed25519.Sign(owner, out.proof())
	return out, nil
}
func (c *Config) verifyChallenge(ch Challenge) error {
	if !c.validEnrollment(ch.Enrollment) || !hexSize(ch.NonceDigest, 32) || len(ch.Ciphertext) == 0 || len(ch.Ciphertext) > 1024 || len(ch.Signature) != ed25519.SignatureSize || !hexSize(ch.Owner, 32) || len(c.owners[ch.Owner]) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	if !ed25519.Verify(c.owners[ch.Owner], ch.proof(), ch.Signature) {
		return ErrInvalid
	}
	return nil
}

// Callers must supply the independently expected enrollment, not blindly copy
// it from an untrusted challenge. The owner is trusted to issue honest random
// challenges; a malicious owner can already grant arbitrary membership.
func AnswerChallenge(c *Config, expected Enrollment, ch Challenge, identity *age.X25519Identity, signer ed25519.PrivateKey) (Admission, error) {
	if c.verifyChallenge(ch) != nil || ch.Enrollment != expected || identity == nil || !validPrivate(signer) || identity.Recipient().String() != expected.Device.Encryption || hex.EncodeToString(signer.Public().(ed25519.PublicKey)) != expected.Device.Signing {
		return Admission{}, ErrInvalid
	}
	reader, err := age.Decrypt(bytes.NewReader(ch.Ciphertext), identity)
	if err != nil {
		return Admission{}, ErrInvalid
	}
	nonce, err := io.ReadAll(io.LimitReader(reader, 33))
	defer clear(nonce)
	if err != nil || len(nonce) != 32 {
		return Admission{}, ErrInvalid
	}
	h := sha256.Sum256(nonce)
	expectedHash, _ := hex.DecodeString(ch.NonceDigest)
	if !hmac.Equal(h[:], expectedHash) {
		return Admission{}, ErrInvalid
	}
	proof := Admission{Challenge: ch, Nonce: bytes.Clone(nonce)}
	proof.Signature = ed25519.Sign(signer, proof.proof())
	return cloneAdmissions([]Admission{proof})[0], nil
}
func VerifyAdmission(c *Config, expected Enrollment, proof Admission) error {
	if c.verifyChallenge(proof.Challenge) != nil || proof.Challenge.Enrollment != expected || len(proof.Nonce) != 32 || len(proof.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	h := sha256.Sum256(proof.Nonce)
	digest, _ := hex.DecodeString(proof.Challenge.NonceDigest)
	if !hmac.Equal(h[:], digest) {
		return ErrInvalid
	}
	key, err := signingKey(expected.Device.Signing)
	if err != nil || !ed25519.Verify(key, proof.proof(), proof.Signature) {
		return ErrInvalid
	}
	return nil
}
func cloneAdmissions(proofs []Admission) []Admission {
	if proofs == nil {
		return nil
	}
	out := make([]Admission, len(proofs))
	copy(out, proofs)
	for i := range out {
		out[i].Nonce = bytes.Clone(out[i].Nonce)
		out[i].Signature = bytes.Clone(out[i].Signature)
		out[i].Challenge.Ciphertext = bytes.Clone(out[i].Challenge.Ciphertext)
		out[i].Challenge.Signature = bytes.Clone(out[i].Challenge.Signature)
	}
	return out
}
func admissionKey(e Enrollment) string { return e.Member + "/" + e.Device.ID }
func orderedAdmissions(proofs []Admission) []Admission {
	out := cloneAdmissions(proofs)
	sort.Slice(out, func(i, j int) bool {
		return admissionKey(out[i].Challenge.Enrollment) < admissionKey(out[j].Challenge.Enrollment)
	})
	return out
}
func (c *Config) verifyAdmissions(p Proposal) error {
	if len(p.Admissions) > 64 || !c.requirePossession && len(p.Admissions) != 0 || p.Mode == "frozen" && len(p.Admissions) != 0 {
		return ErrInvalid
	}
	devices := map[string]Device{}
	for _, m := range p.Members {
		for _, d := range m.Devices {
			devices[m.ID+"/"+d.ID] = d
		}
	}
	previous := ""
	for _, proof := range p.Admissions {
		e := proof.Challenge.Enrollment
		k := admissionKey(e)
		if k <= previous || e.Parent != p.Parent || devices[k] != e.Device || VerifyAdmission(c, e, proof) != nil {
			return ErrInvalid
		}
		previous = k
	}
	return nil
}

// Transition verification also runs on reload, so each admission is consumed
// exactly when that device first enters the signed history. Parent changes
// invalidate pending challenges; this protocol makes no wall-clock TTL claim.
func (c *Config) verifyNewDevices(state *evolution, p Proposal) error {
	if !c.requirePossession {
		return nil
	}
	supplied := map[string]bool{}
	for _, proof := range p.Admissions {
		supplied[admissionKey(proof.Challenge.Enrollment)] = true
	}
	added := 0
	for _, m := range p.Members {
		for _, d := range m.Devices {
			if _, found := state.devices[d.ID]; !found {
				added++
				if !supplied[m.ID+"/"+d.ID] {
					return ErrInvalid
				}
			}
		}
	}
	if added != len(supplied) {
		return ErrInvalid
	}
	return nil
}
