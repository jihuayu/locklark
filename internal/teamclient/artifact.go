package teamclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/jihuayu/locklark/internal/directory"
)

const MaxBootstrapArtifactBytes = 16 << 20

func validateArtifact(a BootstrapArtifact) error {
	if a.Version != 1 || !validSequencer(a.Service) || a.Service.State != BootstrapPending || len(a.Pins.Owners) != 1 || a.Pins.Sequencer != a.Service.Signing || len(a.Proposal.Members) != 1 || len(a.Proposal.Members[0].Devices) != 1 || a.Proposal.Members[0].Role != "writer" || len(a.Proposal.Admissions) != 1 || len(a.Snapshot.Database) > 8<<20 || len(a.Snapshot.Envelope) > 128<<10 {
		return ErrIdentity
	}
	c, e := directory.NewConfigWithWriterACL(a.Pins)
	if e != nil || directory.VerifyInitial(c, a.Proposal, a.Snapshot) != nil {
		return ErrIdentity
	}
	return nil
}

// EncodeBootstrapArtifact returns only public proofs and encrypted snapshot.
func EncodeBootstrapArtifact(a BootstrapArtifact) ([]byte, error) {
	if validateArtifact(a) != nil {
		return nil, ErrIdentity
	}
	raw, e := json.Marshal(a)
	if e != nil || len(raw) > MaxBootstrapArtifactBytes {
		return nil, ErrIdentity
	}
	return raw, nil
}
func DecodeBootstrapArtifact(raw []byte) (BootstrapArtifact, error) {
	var a BootstrapArtifact
	if strictCanonical(raw, &a, MaxBootstrapArtifactBytes) != nil || validateArtifact(a) != nil {
		return BootstrapArtifact{}, ErrIdentity
	}
	return a, nil
}
func artifactDigest(raw []byte) string {
	h := sha256.Sum256(append([]byte("locklark/teamclient/initial-artifact/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}
func artifactMatchesOwner(a BootstrapArtifact, d OwnerDescriptor) bool {
	return samePins(a.Pins, d.Pins) && sameSequencer(a.Service, d.Service) && len(a.Proposal.Members) == 1 && len(a.Proposal.Members[0].Devices) == 1 && a.Proposal.Members[0].ID == d.MemberID && a.Proposal.Members[0].Devices[0] == d.Device.Device && a.Proposal.Owner == d.Owner.Signing
}
