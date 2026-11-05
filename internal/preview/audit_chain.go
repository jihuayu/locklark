package preview

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// V1 is a single-device Ed25519 stream. A dedicated key per stream makes its
// local trust anchor also its identity. Proofs live inside the encrypted vault.
const eventDomain = "locklark/audit-event/v1\x00"
const checkpointDomain = "locklark/audit-checkpoint/v1\x00"

var errAudit = errors.New("audit signature, sequence or witnessed history mismatch")

type checkpoint struct {
	Version   int    `json:"version"`
	Count     int    `json:"count"`
	Head      []byte `json:"head"`
	Signature []byte `json:"signature"`
}
type AuditReport struct {
	Events    int `json:"events"`
	Witnessed int `json:"witnessed"`
}

func eventMessage(prev [32]byte, e Event) []byte {
	// Event v1 is this fixed-order struct of strings/int, using Go JSON escaping.
	b, _ := json.Marshal(e)
	msg := append([]byte(eventDomain), prev[:]...)
	return append(msg, b...)
}
func checkpointMessage(n int, head []byte) []byte {
	msg := binary.BigEndian.AppendUint64([]byte(checkpointDomain), uint64(n))
	return append(msg, head...)
}
func (p *payload) signedRecord(key ed25519.PrivateKey, session, actor, action, reason, result string) {
	var prev [32]byte
	if n := len(p.Proofs); n > 0 {
		prev = sha256.Sum256(p.Proofs[n-1])
	}
	p.record(session, actor, action, reason, result)
	p.Proofs = append(p.Proofs, ed25519.Sign(key, eventMessage(prev, p.Events[len(p.Events)-1])))
}
func makeCheckpoint(p payload, key ed25519.PrivateKey) (checkpoint, error) {
	if _, err := checkChain(p, key.Public().(ed25519.PublicKey), nil); err != nil {
		return checkpoint{}, err
	}
	n := len(p.Proofs)
	head := sha256.Sum256(p.Proofs[n-1])
	return checkpoint{1, n, head[:], ed25519.Sign(key, checkpointMessage(n, head[:]))}, nil
}
func checkChain(p payload, pub ed25519.PublicKey, cp *checkpoint) (AuditReport, error) {
	n := len(p.Events)
	r := AuditReport{Events: n}
	if len(pub) != ed25519.PublicKeySize || n == 0 || n != len(p.Proofs) {
		return AuditReport{}, errAudit
	}
	if cp != nil {
		if cp.Version != 1 || cp.Count <= 0 || cp.Count > n || len(cp.Head) != 32 || !ed25519.Verify(pub, checkpointMessage(cp.Count, cp.Head), cp.Signature) {
			return AuditReport{}, errAudit
		}
		r.Witnessed = cp.Count
	}
	var prev [32]byte
	for i, e := range p.Events {
		if e.Sequence != i+1 || !ed25519.Verify(pub, eventMessage(prev, e), p.Proofs[i]) {
			return AuditReport{}, errAudit
		}
		prev = sha256.Sum256(p.Proofs[i])
		if cp != nil && cp.Count == i+1 && !bytes.Equal(cp.Head, prev[:]) {
			return AuditReport{}, errAudit
		}
	}
	return r, nil
}
func verifyLocalStream(p payload, device string) error {
	pub, err := read(device, "audit.pub", ed25519.PublicKeySize)
	// Historical fixtures had neither a local audit anchor nor a proof stream.
	if errors.Is(err, os.ErrNotExist) && p.Proofs == nil {
		return nil
	}
	if err != nil {
		return errAudit
	}
	_, err = checkChain(p, pub, nil)
	return err
}
func verifyWitness(p payload, device, path string) (AuditReport, error) {
	if path == "" {
		return AuditReport{}, errors.New("trusted checkpoint path required")
	}
	pub, err := read(device, "audit.pub", ed25519.PublicKeySize)
	if err != nil {
		return AuditReport{}, errAudit
	}
	b, err := read(filepath.Dir(path), filepath.Base(path), 2048)
	if err != nil {
		return AuditReport{}, err
	}
	var c checkpoint
	if err = json.Unmarshal(b, &c); err != nil {
		return AuditReport{}, errAudit
	}
	return checkChain(p, pub, &c)
}
func VerifyAudit(bundle, device string, epoch uint64, path string) (AuditReport, error) {
	p, err := readPayload(bundle, device, epoch)
	if err != nil {
		return AuditReport{}, err
	}
	return verifyWitness(p, device, path)
}
