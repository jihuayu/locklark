package main

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

func completeVaultFileCreate(configPath string, manifest vaultFileCreateManifest, session *personal.Session, password, key, kit []byte) error {
	companion, companionExists, err := readVaultFileCreateCompanion(configPath, manifest)
	if err != nil {
		return errVaultFileLocalReview
	}
	journalExists := false
	if _, err := os.Lstat(manifest.Journal); err == nil {
		journalExists = true
	} else if !os.IsNotExist(err) {
		return errVaultFileLocalReview
	}
	if journalExists {
		pending, err := vaultfilejournal.OpenExistingIntent(manifest.Journal)
		if err == nil {
			if pending.Close() != nil {
				return errVaultFileUnknown
			}
		} else {
			if errors.Is(err, vaultfilejournal.ErrLocked) {
				return errVaultFileUnknown
			}
			acked, openErr := vaultfilejournal.OpenExisting(manifest.Journal)
			if openErr != nil {
				if errors.Is(openErr, vaultfilejournal.ErrLocked) {
					return errVaultFileUnknown
				}
				return errVaultFileLocalReview
			}
			if acked.Close() != nil {
				return errVaultFileUnknown
			}
			if !companionExists {
				return errVaultFileLocalReview
			}
			return verifyVaultFileCreateAcked(manifest, companion, session, password, key, kit)
		}
	} else if companionExists {
		return errVaultFileLocalReview
	}

	// The producer creates or verifies one exact intent. It does not open a
	// backend. An already claimed intent remains read-resolve-only below.
	companion, err = ensureVaultFileCreateCompanion(configPath, manifest, session, password, key, kit)
	if err != nil {
		return mapVaultFileCreateGenesisError(err)
	}
	// The durable companion is re-read, then the live Session independently
	// rechecks archive custody, G, local author and recovery reader before the
	// first possible backend Create.
	companion, companionExists, err = readVaultFileCreateCompanion(configPath, manifest)
	if err != nil || !companionExists {
		return errVaultFileLocalUnknown
	}
	req := personal.VaultFileGenesisRequest{VaultID: manifest.VaultID, Name: manifest.Name,
		IntentPath: manifest.Journal, ArchivePath: manifest.Archive}
	public, err := session.PrepareVaultFileGenesis(req, password, key, kit)
	if err != nil {
		return mapVaultFileCreateGenesisError(err)
	}
	if validateVaultFileCreateCompanionPublic(companion, manifest, public) != nil {
		return errVaultFileLocalReview
	}
	journal, err := vaultfilejournal.OpenExistingIntent(manifest.Journal)
	if err != nil {
		return errVaultFileLocalReview
	}
	intent, err := journal.Load()
	if err != nil || !pendingVaultFileCreateIntentMatches(intent, companion, manifest) {
		clear(intent.SealedBytes)
		journal.Close()
		return errVaultFileLocalReview
	}
	clear(intent.SealedBytes)
	rootBytes, ok := decodeVaultFileHex(public.Ownership.OwnerRootPublicKey)
	if !ok {
		journal.Close()
		return errVaultFileLocalReview
	}
	pin := &vaultfile.GenesisRootPin{VaultID: manifest.VaultID,
		OwnerRootKeyID: public.Ownership.OwnerRootKeyID, OwnerRootPublicKey: ed25519.PublicKey(rootBytes)}
	backend, err := vaultfilebackend.OpenDir(manifest.BackendRoot)
	if err != nil {
		journal.Close()
		return errVaultFileBackend
	}
	ctx := context.Background()
	publishErr := vaultfilepublish.PublishGenesisDir(ctx, backend, journal, pin)
	journalCloseErr := journal.Close()
	backendCloseErr := backend.Close()
	if publishErr != nil {
		if errors.Is(publishErr, vaultfilepublish.ErrGenesisReview) || errors.Is(publishErr, vaultfilepublish.ErrVerification) {
			return errVaultFileLocalReview
		}
		return errVaultFileUnknown
	}
	if journalCloseErr != nil || backendCloseErr != nil {
		return errVaultFileUnknown
	}
	if err := verifyVaultFileCreateAcked(manifest, companion, session, password, key, kit); err != nil {
		if errors.Is(err, errVaultFileLocalReview) {
			return err
		}
		// The remote Create and local Ack may already have committed. A
		// failed post-Ack Session check cannot revoke those effects.
		return errVaultFileUnknown
	}
	return nil
}

func pendingVaultFileCreateIntentMatches(intent vaultfilejournal.GenesisIntent, companion vaultFileCreateCompanion, manifest vaultFileCreateManifest) bool {
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

func verifyVaultFileCreateAcked(manifest vaultFileCreateManifest, companion vaultFileCreateCompanion, session *personal.Session, password, key, kit []byte) error {
	gHash, err := hex.DecodeString(companion.GenesisSHA256)
	if err != nil || len(gHash) != sha256.Size {
		return errVaultFileLocalReview
	}
	req := personal.VaultFileGenesisRequest{VaultID: manifest.VaultID, Name: manifest.Name,
		IntentPath: manifest.Journal, ArchivePath: manifest.Archive}
	public, err := session.VerifyAckedVaultFileGenesis(req, gHash, password, key, kit)
	if err != nil {
		return mapVaultFileCreateGenesisError(err)
	}
	if validateVaultFileCreateCompanionPublic(companion, manifest, public) != nil {
		return errVaultFileLocalReview
	}
	// The Session already bound the exact G hash and sole State; this small
	// read binds the companion's public operation ID to that same G.
	j, err := vaultfilejournal.OpenExisting(manifest.Journal)
	if err != nil {
		return errVaultFileLocalReview
	}
	state, loadErr := j.LoadGenesisBaseline()
	closeErr := j.Close()
	if loadErr != nil || closeErr != nil {
		return errVaultFileLocalReview
	}
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	hash := sha256.Sum256(state.BaseBytes)
	file, err := vaultfile.ParseFile(state.BaseBytes)
	if err != nil || !bytes.Equal(hash[:], gHash) || file.Header.OpID != companion.OperationID {
		return errVaultFileLocalReview
	}
	return nil
}

func mapVaultFileCreateGenesisError(err error) error {
	switch {
	case errors.Is(err, personal.ErrVaultFileGenesisUnknown), errors.Is(err, vaultfilejournal.ErrCreateUnknown):
		return errVaultFileUnknown
	case errors.Is(err, personal.ErrVaultFileGenesisIntent):
		return errVaultFileLocalReview
	case errors.Is(err, vaultfilejournal.ErrUnsupported):
		return errVaultFileUnsupported
	default:
		return errVaultFileVerification
	}
}
