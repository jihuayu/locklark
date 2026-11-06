package teamclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/teamsync"
)

func serviceTarget(p directory.Pins, scope, digest, db, anchor string) string {
	raw, _ := json.Marshal(struct {
		Pins                             directory.Pins
		Scope, Digest, Directory, Anchor string
	}{p, scope, digest, db, anchor})
	h := sha256.Sum256(append([]byte("locklark/teamclient/sequencer-scope-adoption/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}
func checkedInit(path string, r profileRecord, q ServiceInitRequest) (ServiceInitRequest, []byte, error) {
	if r.Kind != "sequencer" || !validSequencer(q.Expected) || !sameSequencer(*r.Sequencer, q.Expected) || !sameSequencer(q.Artifact.Service, q.Expected) {
		return q, nil, ErrBootstrapConflict
	}
	p, c, e := normalizedPins(q.TrustedPins)
	if e != nil || len(p.Owners) != 1 || p.Sequencer != q.Expected.Signing {
		return q, nil, ErrIdentity
	}
	q.TrustedPins = p
	stored, _, e := normalizedPins(q.Artifact.Pins)
	if e != nil || !samePins(p, stored) || q.Artifact.Proposal.Scope != c.Genesis().Scope {
		return q, nil, ErrBootstrapConflict
	}
	raw, e := EncodeBootstrapArtifact(q.Artifact)
	if e != nil {
		return q, nil, e
	}
	q.Directory, e = canonicalProfilePath(q.Directory)
	if e != nil {
		return q, nil, e
	}
	q.Anchor, e = canonicalProfilePath(q.Anchor)
	if e != nil {
		return q, nil, e
	}
	if !distinctPaths(path, path+".identity-lease", q.Directory, q.Anchor) || trustedProfileParent(filepath.Dir(q.Directory)) != nil || trustedProfileParent(filepath.Dir(q.Anchor)) != nil {
		return q, nil, ErrProfile
	}
	return q, raw, nil
}
func absent(path string) bool { _, e := os.Lstat(path); return os.IsNotExist(e) }
func exactInitialization(r profileRecord, c *directory.Config, a BootstrapArtifact) (directory.Receipt, error) {
	if r.Init == nil {
		return directory.Receipt{}, ErrProfile
	}
	h, e := directory.ExportHistory(r.Init.Directory, c, c.Genesis())
	if e != nil {
		return directory.Receipt{}, ErrBootstrapUnknown
	}
	if _, e = directory.VerifyHistory(c, c.Genesis(), h); e != nil || len(h.Receipts) == 0 {
		return directory.Receipt{}, ErrBootstrapUnknown
	}
	one, _ := json.Marshal(h.Receipts[0].Proposal)
	want, _ := json.Marshal(a.Proposal)
	if !bytes.Equal(one, want) {
		return directory.Receipt{}, ErrBootstrapConflict
	}
	if r.Phase != BootstrapActive {
		x, _ := json.Marshal(h.Snapshot)
		y, _ := json.Marshal(a.Snapshot)
		if len(h.Receipts) != 1 || !bytes.Equal(x, y) {
			return directory.Receipt{}, ErrBootstrapConflict
		}
	}
	return h.Receipts[0], nil
}

// InitializeService is an explicit local operation. TrustedPins and Expected
// must be independently reviewed; neither is discovered from the artifact.
func InitializeService(ctx context.Context, path string, q ServiceInitRequest, s SystemStore) (InitResult, error) {
	return initializeService(ctx, path, q, s, false)
}
func ReconcileServiceInitialization(ctx context.Context, path string, q ServiceInitRequest, s SystemStore) (InitResult, error) {
	return initializeService(ctx, path, q, s, true)
}
func initializeService(ctx context.Context, path string, q ServiceInitRequest, s SystemStore, reconcile bool) (out InitResult, err error) {
	if ctx == nil || ctx.Err() != nil || s == nil {
		return out, ErrCancelled
	}
	lease, e := openProfile(path)
	if e != nil {
		return out, e
	}
	defer func() {
		if lease.close() != nil {
			out.State = BootstrapUnknown
			out.Checkpoint = directory.Checkpoint{}
			err = ErrBootstrapUnknown
		}
	}()
	r, e := lease.load()
	if e != nil {
		return out, e
	}
	q, raw, e := checkedInit(r.Path, r, q)
	if e != nil {
		return out, e
	}
	digest := artifactDigest(raw)
	out.ArtifactDigest = digest
	if r.Init != nil {
		if !bytes.Equal(r.Init.Artifact, raw) || r.Init.Digest != digest || r.Init.Directory != q.Directory || r.Init.Anchor != q.Anchor {
			return InitResult{}, ErrBootstrapConflict
		}
	} else if reconcile {
		return InitResult{}, ErrBootstrapConflict
	}
	if r.Roles["sequencer"] == BootstrapPreparing {
		return out, ErrBootstrapUnknown
	}
	// A positive, exact OS load is the authority. A failed Load never means
	// absent and never authorizes replacing an existing protected identity.
	sealed, e := loadRaw(ctx, s, r, "sequencer")
	if e != nil {
		return out, e
	}
	defer clear(sealed)
	b, id, _ := bindingFor(r, "sequencer")
	seed, bound, e := decodeSequencer(b, sealed)
	if e != nil {
		return out, e
	}
	defer clear(seed)
	desired := serviceTarget(q.TrustedPins, q.Artifact.Proposal.Scope, digest, q.Directory, q.Anchor)
	if bound != "" && bound != desired {
		return InitResult{}, ErrBootstrapConflict
	}
	boundRaw, e := encodeSequencer(b, seed, desired)
	if e != nil {
		return out, e
	}
	defer clear(boundRaw)
	if r.Init == nil {
		if !absent(q.Directory) || !absent(q.Anchor) {
			return out, ErrBootstrapConflict
		}
		r.Init = &serviceIntent{Artifact: raw, Digest: digest, Directory: q.Directory, Anchor: q.Anchor}
		r.Phase = BootstrapUnknown
		if lease.save(&r) != nil {
			return out, ErrBootstrapUnknown
		}
	}
	out.State = BootstrapUnknown
	if ctx.Err() != nil {
		return out, ErrCancelled
	}
	c, _ := directory.NewConfigWithWriterACL(q.TrustedPins)
	var anchors *teamsync.FileAnchorStore
	freshBind := false
	if bound == "" {
		if r.Init.AdoptionAttempt {
			return out, ErrBootstrapUnknown
		}
		if absent(q.Anchor) {
			anchors, e = teamsync.CreateFileAnchorStore(q.Anchor, c.Genesis())
		} else {
			anchors, e = teamsync.OpenFileAnchorStore(q.Anchor)
		}
		if e != nil {
			return out, ErrBootstrapUnknown
		}
		cp, e := anchors.Load()
		if e != nil || cp != c.Genesis() {
			return out, ErrBootstrapConflict
		}
		if ctx.Err() != nil {
			return out, ErrCancelled
		}
		r.Init.AdoptionAttempt = true
		if lease.save(&r) != nil {
			return out, ErrBootstrapUnknown
		}
		// Irreversible start permission was durably recorded. Cancellation or
		// partial replacement from this point is unknown, never a second Store.
		if s.Store(id, boundRaw) != nil {
			return out, ErrBootstrapUnknown
		}
		if ctx.Err() != nil {
			return out, ErrCancelled
		}
		freshBind = true
	} else if !r.Init.AdoptionAttempt {
		r.Init.AdoptionAttempt = true
		if lease.save(&r) != nil {
			return out, ErrBootstrapUnknown
		}
	}
	if anchors == nil {
		anchors, e = teamsync.OpenFileAnchorStore(q.Anchor)
		if e != nil {
			return out, ErrBootstrapUnknown
		}
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	if freshBind && !r.Init.CreateAttempt {
		if !absent(q.Directory) {
			return out, ErrBootstrapConflict
		}
		if ctx.Err() != nil {
			return out, ErrCancelled
		}
		r.Init.CreateAttempt = true
		if lease.save(&r) != nil {
			return out, ErrBootstrapUnknown
		}
		receipt, e := directory.Create(q.Directory, c, key, q.Artifact.Proposal, q.Artifact.Snapshot)
		if e != nil {
			return out, ErrBootstrapUnknown
		}
		if ctx.Err() != nil {
			return out, ErrCancelled
		}
		r.Init.Receipt = &receipt
		if lease.save(&r) != nil {
			return out, ErrBootstrapUnknown
		}
	}
	// Existing DB recovery verifies the full original initial transition. A
	// missing DB after Create-attempt stays unknown: no re-sign or Create retry.
	receipt, e := exactInitialization(r, c, q.Artifact)
	if e != nil {
		return out, e
	}
	if r.Init.Receipt != nil {
		x, _ := json.Marshal(r.Init.Receipt)
		y, _ := json.Marshal(receipt)
		if !bytes.Equal(x, y) {
			return out, ErrBootstrapConflict
		}
	} else {
		r.Init.Receipt = &receipt
		if lease.save(&r) != nil {
			return out, ErrBootstrapUnknown
		}
	}
	cp, e := anchors.Load()
	if e != nil || !c.ValidCheckpoint(cp) {
		return out, ErrBootstrapUnknown
	}
	if cp == c.Genesis() {
		if anchors.Advance(cp, receipt.Checkpoint()) != nil {
			return out, ErrBootstrapUnknown
		}
		cp = receipt.Checkpoint()
	}
	if r.Phase != BootstrapActive && cp != receipt.Checkpoint() {
		return out, ErrBootstrapConflict
	}
	if _, e = directory.Read(q.Directory, c, cp); e != nil {
		return out, ErrBootstrapUnknown
	}
	if ctx.Err() != nil {
		return out, ErrCancelled
	}
	r.Phase = BootstrapActive
	r.Roles["sequencer"] = BootstrapPending
	if lease.save(&r) != nil {
		return out, ErrBootstrapUnknown
	}
	if ctx.Err() != nil {
		return out, ErrCancelled
	}
	return InitResult{State: BootstrapActive, Checkpoint: cp, ArtifactDigest: digest}, nil
}

func ReadSequencerDescriptor(path string) (SequencerDescriptor, error) {
	lease, e := openProfile(path)
	if e != nil {
		return SequencerDescriptor{}, e
	}
	r, e := lease.load()
	closed := lease.close()
	if e != nil || closed != nil || r.Kind != "sequencer" {
		return SequencerDescriptor{}, ErrProfile
	}
	d := *r.Sequencer
	d.State = r.Phase
	return d, nil
}
