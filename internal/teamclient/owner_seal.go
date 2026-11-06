package teamclient

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
)

const ownerSealDomain = "locklark/teamclient/protected-owner/v1\x00"

type ownerMarker struct {
	Version        int    `json:"version"`
	Identity       string `json:"identity"`
	Stage          string `json:"stage"`
	BuildID        string `json:"build_id,omitempty"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
}

func validOwnerMarker(m ownerMarker) bool {
	if m.Version != 1 || !validHex(m.Identity, 32) {
		return false
	}
	switch m.Stage {
	case "unbuilt":
		return m.BuildID == "" && m.ArtifactDigest == ""
	case "claimed":
		return validHex(m.BuildID, 16) && m.ArtifactDigest == ""
	case "built":
		return validHex(m.BuildID, 16) && validHex(m.ArtifactDigest, 32)
	}
	return false
}
func encodeOwnerRole(b roleBinding, seed []byte, m ownerMarker) ([]byte, error) {
	m.Version = 1
	m.Identity = roleDigest(b)
	if len(seed) != 32 || !validOwnerMarker(m) {
		return nil, ErrIdentity
	}
	public, e := json.Marshal(m)
	if e != nil {
		return nil, ErrIdentity
	}
	raw := appendFrame([]byte(ownerSealDomain), public)
	raw = appendFrame(raw, seed)
	if len(raw) > maxProtectedRoleBytes {
		clear(raw)
		return nil, ErrIdentity
	}
	return raw, nil
}
func decodeOwnerRole(b roleBinding, raw []byte) ([]byte, ownerMarker, error) {
	if len(raw) > maxProtectedRoleBytes || !bytes.HasPrefix(raw, []byte(ownerSealDomain)) {
		return nil, ownerMarker{}, ErrIdentity
	}
	rest := raw[len(ownerSealDomain):]
	if len(rest) < 4 {
		return nil, ownerMarker{}, ErrIdentity
	}
	n := binary.BigEndian.Uint32(rest)
	rest = rest[4:]
	if uint64(n) > uint64(len(rest)) {
		return nil, ownerMarker{}, ErrIdentity
	}
	var marker ownerMarker
	if strictCanonical(rest[:n], &marker, 1024) != nil || !validOwnerMarker(marker) || marker.Identity != roleDigest(b) {
		return nil, ownerMarker{}, ErrIdentity
	}
	rest = rest[n:]
	if len(rest) != 4+32 || binary.BigEndian.Uint32(rest) != 32 {
		return nil, ownerMarker{}, ErrIdentity
	}
	key := ed25519.NewKeyFromSeed(rest[4:])
	defer clear(key)
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != b.Descriptor.Signing {
		return nil, ownerMarker{}, ErrIdentity
	}
	return bytes.Clone(rest[4:]), marker, nil
}
