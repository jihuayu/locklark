package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// VerifyAckedVaultFileGenesis authenticates the exact generation-0 journal
// base against a caller-persisted G hash and this Session's current custody.
// The full recovery archive, independent kit, local owner slot and recovery
// slot are verified again. The returned projection is public metadata only.
// It proves a locally recorded readback/Ack, not that req.Name is still the
// remote head, that its revision is fresh, or that a SaaS grant exists. The
// caller must supply the original G hash from an independent durable record;
// neither the journal nor the G itself may supply that expected value.
func (s *Session) VerifyAckedVaultFileGenesis(req VaultFileGenesisRequest, expectedGHash, password, key, recoveryMaterial []byte) (VaultFileGenesisPublic, error) {
	return s.verifyAckedVaultFileGenesisWith(req, expectedGHash, password, key, recoveryMaterial, nil)
}

// beforeFinish is an unexported test seam with no material arguments or
// results. The production entry always passes nil.
func (s *Session) verifyAckedVaultFileGenesisWith(req VaultFileGenesisRequest, expectedGHash, password, key, recoveryMaterial []byte, beforeFinish func()) (VaultFileGenesisPublic, error) {
	var out VaultFileGenesisPublic
	if s == nil {
		return out, ErrSessionLocked
	}
	if !idOK(req.VaultID) || !vaultfilebackend.ValidName(req.Name) ||
		!validVaultFileGenesisPath(req.IntentPath) || !validVaultFileGenesisPath(req.ArchivePath) ||
		req.IntentPath == req.ArchivePath || len(expectedGHash) != sha256.Size {
		return out, ErrVaultFileGenesisIntent
	}
	s.mu.Lock()
	if err := s.active(true); err != nil {
		s.mu.Unlock()
		return out, err
	}
	if s.requireFreshFullFactor() != nil {
		s.mu.Unlock()
		return out, ErrVaultFileFullFactorRequired
	}
	s.mu.Unlock()

	// Disk and cryptographic work stay outside Session.mu, so RequestLock
	// can cancel a pending verification before its short completion gate.
	archived, err := decodeArchive(req.ArchivePath, string(password), key, string(recoveryMaterial))
	if err != nil {
		return out, ErrVaultFileGenesisRecovery
	}
	defer clearDecodedArchiveSensitive(archived)
	var archivedOwner *vaultFileOwnerRecord
	for i := range archived.VaultFileOwners {
		if archived.VaultFileOwners[i].VaultID == req.VaultID {
			archivedOwner = &archived.VaultFileOwners[i]
			break
		}
	}
	if archivedOwner == nil {
		return out, ErrVaultFileGenesisRecovery
	}
	material, err := s.loadVaultFileGenesisMaterial(req.VaultID, *archivedOwner)
	if err != nil {
		return out, err
	}
	defer material.clear()
	journal, err := vaultfilejournal.OpenExisting(req.IntentPath)
	if err != nil {
		return out, ErrVaultFileGenesisIntent
	}
	state, loadErr := journal.LoadGenesisBaseline()
	closeErr := journal.Close()
	if loadErr != nil || closeErr != nil {
		return out, ErrVaultFileGenesisIntent
	}
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	gotHash := sha256.Sum256(state.BaseBytes)
	if !bytes.Equal(gotHash[:], expectedGHash) {
		return out, ErrVaultFileGenesisIntent
	}
	root := ed25519.NewKeyFromSeed(material.owner.OwnerRootSeed)
	rootPin := &vaultfile.GenesisRootPin{VaultID: req.VaultID,
		OwnerRootKeyID:     material.owner.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(root.Public().(ed25519.PublicKey))}
	clear(root)
	file, err := vaultfile.ParseFile(state.BaseBytes)
	if err != nil {
		return out, ErrVaultFileGenesisIntent
	}
	intent := vaultfilejournal.GenesisIntent{Name: req.Name, VaultID: req.VaultID,
		OwnerRootKeyID: rootPin.OwnerRootKeyID, OwnerRootPublicKey: rootPin.OwnerRootPublicKey,
		PolicySeq: 0, PolicyDigest: file.Header.PolicyDigest, OperationID: file.Header.OpID,
		SealedBytes: state.BaseBytes}
	checkpoint, err := verifyVaultFileGenesisIntent(req, intent, material.owner,
		material.localSigning, material.localAgeIdentity, material.localRecipient, rootPin)
	if err != nil {
		return out, ErrVaultFileGenesisIntent
	}
	out = VaultFileGenesisPublic{Ownership: material.projection, PolicyDigest: hex.EncodeToString(checkpoint.PolicyDigest)}
	if beforeFinish != nil {
		beforeFinish()
	}

	// Reopen after expensive verification and retain the journal's exclusive
	// lock through the Session completion gate. Another cooperating process
	// cannot replace the exact local baseline between this check and finish.
	journal, err = vaultfilejournal.OpenExisting(req.IntentPath)
	if err != nil {
		return VaultFileGenesisPublic{}, ErrVaultFileGenesisIntent
	}
	final, loadErr := journal.LoadGenesisBaseline()
	defer clear(final.BaseBytes)
	defer clear(final.WorkingBytes)
	if loadErr != nil || final.Generation != state.Generation || final.RemoteRevision != state.RemoteRevision ||
		!bytes.Equal(final.BaseBytes, state.BaseBytes) || !bytes.Equal(final.WorkingBytes, state.WorkingBytes) {
		journal.Close()
		return VaultFileGenesisPublic{}, ErrVaultFileGenesisIntent
	}
	s.mu.Lock()
	rechecked, err := s.loadVaultFileGenesisMaterialLocked(req.VaultID, *archivedOwner)
	if err != nil || !bytes.Equal(rechecked.localSigning, material.localSigning) ||
		!bytes.Equal(rechecked.localAgeIdentity, material.localAgeIdentity) ||
		rechecked.localRecipient != material.localRecipient {
		rechecked.clear()
		s.mu.Unlock()
		journal.Close()
		return VaultFileGenesisPublic{}, ErrVaultFileGenesisIntent
	}
	rechecked.clear()
	s.saveMu.Lock()
	valid := !s.lockRequested.Load() && len(s.material) != 0 && !s.idleExpired(time.Now()) && s.requireFreshFullFactor() == nil
	s.saveMu.Unlock()
	s.mu.Unlock()
	if journal.Close() != nil {
		return VaultFileGenesisPublic{}, ErrVaultFileGenesisIntent
	}
	if !valid {
		return VaultFileGenesisPublic{}, ErrVaultFileFullFactorRequired
	}
	return out, nil
}
