package teamclient

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
)

const sequencerSealDomain = "locklark/teamclient/protected-sequencer/v1\x00"

type sequencerBinding struct {
	Version  int    `json:"version"`
	Identity string `json:"identity"`
	Stage    string `json:"stage"`
	Target   string `json:"target,omitempty"`
}

func encodeSequencer(b roleBinding, seed []byte, target string) ([]byte, error) {
	if len(seed) != 32 || target != "" && !validHex(target, 32) {
		return nil, ErrIdentity
	}
	stage := "unbound"
	if target != "" {
		stage = "bound"
	}
	sealed := sequencerBinding{1, roleDigest(b), stage, target}
	public, e := json.Marshal(sealed)
	if e != nil {
		return nil, ErrIdentity
	}
	raw := appendFrame([]byte(sequencerSealDomain), public)
	raw = appendFrame(raw, seed)
	if len(raw) > maxProtectedRoleBytes {
		clear(raw)
		return nil, ErrIdentity
	}
	return raw, nil
}
func decodeSequencer(b roleBinding, raw []byte) (seed []byte, target string, err error) {
	if len(raw) > maxProtectedRoleBytes || !bytes.HasPrefix(raw, []byte(sequencerSealDomain)) {
		return nil, "", ErrIdentity
	}
	rest := raw[len(sequencerSealDomain):]
	if len(rest) < 4 {
		return nil, "", ErrIdentity
	}
	n := binary.BigEndian.Uint32(rest)
	rest = rest[4:]
	if uint64(n) > uint64(len(rest)) {
		return nil, "", ErrIdentity
	}
	var public sequencerBinding
	if strictCanonical(rest[:n], &public, 1024) != nil || public.Version != 1 || public.Identity != roleDigest(b) || public.Stage != "unbound" && public.Stage != "bound" || public.Stage == "unbound" && public.Target != "" || public.Stage == "bound" && !validHex(public.Target, 32) {
		return nil, "", ErrIdentity
	}
	rest = rest[n:]
	if len(rest) != 4+ed25519.SeedSize || binary.BigEndian.Uint32(rest) != ed25519.SeedSize {
		return nil, "", ErrIdentity
	}
	key := ed25519.NewKeyFromSeed(rest[4:])
	defer clear(key)
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != b.Descriptor.Signing {
		return nil, "", ErrIdentity
	}
	return bytes.Clone(rest[4:]), public.Target, nil
}
