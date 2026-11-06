package teamclient

import (
	"context"
	"github.com/jihuayu/locklark/internal/directory"
)

// BootstrapStatus is unverified recorded local state, not a network freshness
// statement or authorization. No private material or provider errors appear.
type BootstrapStatus struct {
	Kind           string                    `json:"kind"`
	ProfilePath    string                    `json:"profile_path"`
	RecordedState  BootstrapPhase            `json:"recorded_state"`
	Roles          map[string]BootstrapPhase `json:"roles"`
	Sequencer      *SequencerDescriptor      `json:"sequencer,omitempty"`
	Owner          *OwnerDescriptor          `json:"owner,omitempty"`
	ArtifactDigest string                    `json:"artifact_digest,omitempty"`
	BuildID        string                    `json:"build_id,omitempty"`
	Initialization *InitializationStatus     `json:"initialization,omitempty"`
}
type InitializationStatus struct {
	ArtifactDigest  string               `json:"artifact_digest"`
	Directory       string               `json:"directory"`
	Anchor          string               `json:"anchor"`
	AdoptionAttempt bool                 `json:"adoption_attempt"`
	CreateAttempt   bool                 `json:"create_attempt"`
	Checkpoint      directory.Checkpoint `json:"checkpoint"`
}

func statusOf(r profileRecord) BootstrapStatus {
	s := BootstrapStatus{Kind: r.Kind, ProfilePath: r.Path, RecordedState: r.Phase, Roles: make(map[string]BootstrapPhase)}
	s.BuildID = r.BuildID
	for role, state := range r.Roles {
		s.Roles[role] = state
	}
	if r.Sequencer != nil {
		d := *r.Sequencer
		d.State = r.Phase
		s.Sequencer = &d
	}
	if r.Owner != nil {
		d := cloneOwner(*r.Owner)
		d.State = r.Phase
		s.Owner = &d
	}
	if len(r.Artifact) > 0 {
		s.ArtifactDigest = artifactDigest(r.Artifact)
	}
	if r.Init != nil {
		i := r.Init
		s.Initialization = &InitializationStatus{ArtifactDigest: i.Digest, Directory: i.Directory, Anchor: i.Anchor, AdoptionAttempt: i.AdoptionAttempt, CreateAttempt: i.CreateAttempt}
		s.ArtifactDigest = i.Digest
		if i.Receipt != nil {
			s.Initialization.Checkpoint = i.Receipt.Checkpoint()
		}
	}
	return s
}
func ReadBootstrapStatus(path string) (BootstrapStatus, error) {
	lease, e := openProfile(path)
	if e != nil {
		return BootstrapStatus{}, e
	}
	r, e := lease.load()
	closed := lease.close()
	if e != nil || closed != nil {
		return BootstrapStatus{}, ErrProfile
	}
	return statusOf(r), nil
}
func ReadOwnerDescriptor(path string) (OwnerDescriptor, error) {
	o, e := OpenOwnerBootstrap(path)
	if e != nil {
		return OwnerDescriptor{}, e
	}
	defer o.Close()
	return o.Descriptor(), nil
}

// ReconcileProtection only loads existing original records. A preparing role
// has no recoverable OS-start evidence; it is never filled with a replacement.
func ReconcileProtection(ctx context.Context, path string, s SystemStore) (out BootstrapStatus, err error) {
	if ctx == nil || ctx.Err() != nil || s == nil {
		return out, ErrCancelled
	}
	lease, e := openProfile(path)
	if e != nil {
		return out, e
	}
	defer func() {
		if lease.close() != nil {
			out = BootstrapStatus{}
			err = ErrBootstrapUnknown
		}
	}()
	r, e := lease.load()
	if e != nil {
		return out, e
	}
	roles := []string{"sequencer"}
	if r.Kind == "owner" {
		roles = []string{"owner", "publisher", "device"}
	}
	for _, role := range roles {
		if r.Roles[role] == BootstrapPreparing {
			return statusOf(r), ErrBootstrapUnknown
		}
		raw, e := loadRaw(ctx, s, r, role)
		if e == nil && role == "owner" {
			b, _, _ := bindingFor(r, role)
			seed, marker, de := decodeOwnerRole(b, raw)
			clear(seed)
			if de != nil {
				e = de
			} else if marker.Stage == "claimed" || marker.Stage == "built" && (len(r.Artifact) == 0 || r.BuildID != marker.BuildID || artifactDigest(r.Artifact) != marker.ArtifactDigest) || marker.Stage == "unbuilt" && r.BuildAttempt {
				e = ErrBootstrapUnknown
			}
		}
		clear(raw)
		if e != nil {
			return statusOf(r), e
		}
		r.Roles[role] = BootstrapPending
	}
	if r.Phase != BootstrapActive && r.Init == nil && (!r.BuildAttempt || len(r.Artifact) > 0) {
		r.Phase = BootstrapPending
	}
	if ctx.Err() != nil {
		return statusOf(r), ErrCancelled
	}
	if lease.save(&r) != nil {
		return statusOf(r), ErrBootstrapUnknown
	}
	if ctx.Err() != nil {
		return statusOf(r), ErrCancelled
	}
	return statusOf(r), nil
}
