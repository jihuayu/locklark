package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

func (c *CreationContext) completeCreate(ctx context.Context, password, key, kit []byte) error {
	manifest := c.manifest
	companion, companionExists, err := ReadCompanion(c.configPath, manifest)
	if err != nil {
		return ErrLocalReview
	}
	journalExists := false
	if _, err := os.Lstat(manifest.Journal); err == nil {
		journalExists = true
	} else if !os.IsNotExist(err) {
		return ErrLocalReview
	}
	if journalExists {
		pending, err := vaultfilejournal.OpenExistingIntent(manifest.Journal)
		if err == nil {
			if pending.Close() != nil {
				return ErrCreateUnknown
			}
		} else {
			if errors.Is(err, vaultfilejournal.ErrLocked) {
				return ErrCreateUnknown
			}
			acked, openErr := vaultfilejournal.OpenExisting(manifest.Journal)
			if openErr != nil {
				if errors.Is(openErr, vaultfilejournal.ErrLocked) {
					return ErrCreateUnknown
				}
				return ErrLocalReview
			}
			if acked.Close() != nil {
				return ErrCreateUnknown
			}
			if !companionExists {
				return ErrLocalReview
			}
			return c.verifyCreateAcked(companion, password, key, kit)
		}
	} else if companionExists {
		return ErrLocalReview
	}

	// The producer creates or verifies one exact intent. It does not open a
	// backend. An already claimed intent remains read-resolve-only below.
	companion, err = c.ensureCreateCompanion(password, key, kit)
	if err != nil {
		return mapCreateGenesisError(err)
	}
	if c.afterIntentForTest != nil {
		c.afterIntentForTest()
	}
	// The durable companion is re-read, then the live Session independently
	// rechecks archive custody, G, local author and recovery reader before the
	// first possible backend Create.
	companion, companionExists, err = ReadCompanion(c.configPath, manifest)
	if err != nil || !companionExists {
		return ErrLocalUnknown
	}
	req := personal.VaultFileGenesisRequest{VaultID: manifest.VaultID, Name: manifest.Name,
		IntentPath: manifest.Journal, ArchivePath: manifest.Archive}
	public, err := c.session.PrepareVaultFileGenesis(req, password, key, kit)
	if err != nil {
		return mapCreateGenesisError(err)
	}
	if validateCreateCompanionPublic(companion, manifest, public) != nil {
		return ErrLocalReview
	}
	journal, err := vaultfilejournal.OpenExistingIntent(manifest.Journal)
	if err != nil {
		return ErrLocalReview
	}
	intent, err := journal.Load()
	if err != nil || !pendingCreateIntentMatches(intent, companion, manifest) {
		clear(intent.SealedBytes)
		journal.Close()
		return ErrLocalReview
	}
	clear(intent.SealedBytes)
	rootBytes, ok := DecodeHex(public.Ownership.OwnerRootPublicKey)
	if !ok {
		journal.Close()
		return ErrLocalReview
	}
	pin := &vaultfile.GenesisRootPin{VaultID: manifest.VaultID,
		OwnerRootKeyID: public.Ownership.OwnerRootKeyID, OwnerRootPublicKey: ed25519.PublicKey(rootBytes)}
	if _, err := c.checkManifest(); err != nil {
		journal.Close()
		return err
	}
	if err := c.fresh(); err != nil {
		journal.Close()
		return err
	}
	if ctx.Err() != nil {
		journal.Close()
		return ErrCreateUnknown
	}
	backend, err := vaultfilebackend.OpenDir(manifest.BackendRoot)
	if err != nil {
		journal.Close()
		return ErrBackend
	}
	if err := c.fresh(); err != nil || ctx.Err() != nil {
		backend.Close()
		journal.Close()
		if ctx.Err() != nil {
			return ErrCreateUnknown
		}
		return err
	}
	publishErr := vaultfilepublish.PublishGenesisDir(ctx, backend, journal, pin)
	journalCloseErr := journal.Close()
	backendCloseErr := backend.Close()
	if publishErr != nil {
		if errors.Is(publishErr, vaultfilepublish.ErrGenesisReview) || errors.Is(publishErr, vaultfilepublish.ErrVerification) {
			return ErrLocalReview
		}
		return ErrCreateUnknown
	}
	if journalCloseErr != nil || backendCloseErr != nil {
		return ErrCreateUnknown
	}
	if err := c.verifyCreateAcked(companion, password, key, kit); err != nil {
		if errors.Is(err, ErrLocalReview) {
			return err
		}
		// The remote Create and local Ack may already have committed. A
		// failed post-Ack Session check cannot revoke those effects.
		return ErrCreateUnknown
	}
	return nil
}

func pendingCreateIntentMatches(intent vaultfilejournal.GenesisIntent, companion Companion, manifest Manifest) bool {
	hash := sha256.Sum256(intent.SealedBytes)
	cp := companion.Resume.Checkpoint
	return cp != nil && cp.PolicySeq != nil && *cp.PolicySeq == 0 &&
		intent.Name == manifest.Name && intent.VaultID == manifest.VaultID &&
		intent.OwnerRootKeyID == cp.OwnerRootKeyID && intent.PolicySeq == 0 &&
		intent.OperationID == companion.OperationID &&
		hex.EncodeToString(hash[:]) == companion.GenesisSHA256 &&
		hex.EncodeToString(intent.OwnerRootPublicKey) == cp.OwnerRootPublicKey &&
		hex.EncodeToString(intent.PolicyDigest) == cp.PolicyDigest
}

func (c *CreationContext) verifyCreateAcked(companion Companion, password, key, kit []byte) error {
	manifest := c.manifest
	if _, err := c.checkManifest(); err != nil {
		return err
	}
	gHash, err := hex.DecodeString(companion.GenesisSHA256)
	if err != nil || len(gHash) != sha256.Size {
		return ErrLocalReview
	}
	req := personal.VaultFileGenesisRequest{VaultID: manifest.VaultID, Name: manifest.Name,
		IntentPath: manifest.Journal, ArchivePath: manifest.Archive}
	public, err := c.session.VerifyAckedVaultFileGenesis(req, gHash, password, key, kit)
	if err != nil {
		return mapCreateGenesisError(err)
	}
	if validateCreateCompanionPublic(companion, manifest, public) != nil {
		return ErrLocalReview
	}
	// The Session already bound the exact G hash and sole State; this small
	// read binds the companion's public operation ID to that same G.
	j, err := vaultfilejournal.OpenExisting(manifest.Journal)
	if err != nil {
		return ErrLocalReview
	}
	state, loadErr := j.LoadGenesisBaseline()
	closeErr := j.Close()
	if loadErr != nil || closeErr != nil {
		return ErrLocalReview
	}
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	hash := sha256.Sum256(state.BaseBytes)
	file, err := vaultfile.ParseFile(state.BaseBytes)
	if err != nil || !bytes.Equal(hash[:], gHash) || file.Header.OpID != companion.OperationID {
		return ErrLocalReview
	}
	if _, err := c.checkManifest(); err != nil {
		return err
	}
	return nil
}

func mapCreateGenesisError(err error) error {
	switch {
	case errors.Is(err, personal.ErrVaultFileGenesisUnknown), errors.Is(err, vaultfilejournal.ErrCreateUnknown):
		return ErrCreateUnknown
	case errors.Is(err, personal.ErrVaultFileGenesisIntent):
		return ErrLocalReview
	case errors.Is(err, ErrLocalReview):
		return ErrLocalReview
	case errors.Is(err, ErrLocalUnknown):
		return ErrCreateUnknown
	case errors.Is(err, vaultfilejournal.ErrUnsupported):
		return ErrCreateUnsupported
	default:
		return ErrCreateVerification
	}
}
