package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	bolt "go.etcd.io/bbolt"
)

var ErrVaultFileGenesisRecovery = errors.New("vault-file genesis recovery proof rejected")
var ErrVaultFileGenesisIntent = errors.New("vault-file genesis intent needs review")
var ErrVaultFileGenesisUnknown = errors.New("vault-file genesis intent outcome unknown; reopen before retry")

// VaultFileGenesisRequest names already persisted caller state. VaultID must
// have been used to prepare ownership custody before the recovery backup was
// published. Neither the archive path nor the intent is a trust anchor.
type VaultFileGenesisRequest struct {
	VaultID     string
	Name        string
	IntentPath  string
	ArchivePath string
}

// VaultFileGenesisPublic contains only enrollment metadata and a genesis
// policy digest. It proves no remote publication, freshness or grant.
type VaultFileGenesisPublic struct {
	Ownership    VaultFileOwnershipPublic `json:"ownership"`
	PolicyDigest string                   `json:"policy_digest"`
}

// PrepareVaultFileGenesis authenticates a published backup with its complete
// independent recovery material, proves its exact private owner/recovery
// custody equals the current personal vault's custody, seals a real empty
// genesis, opens it with the recovery device, and exclusively saves its exact
// bytes as a local intent. A retry rechecks the backup and the existing G;
// it never re-seals or replaces an existing intent. It does not open a backend.
// Password, Secret Key and recovery material are transient caller inputs; no
// private key, KDBX handle, sealed bytes or callback leaves this Session API.
func (s *Session) PrepareVaultFileGenesis(req VaultFileGenesisRequest, password, key, recoveryMaterial []byte) (VaultFileGenesisPublic, error) {
	var out VaultFileGenesisPublic
	if s == nil {
		return out, ErrSessionLocked
	}
	if !idOK(req.VaultID) || !vaultfilebackend.ValidName(req.Name) ||
		!validVaultFileGenesisPath(req.IntentPath) || !validVaultFileGenesisPath(req.ArchivePath) ||
		req.IntentPath == req.ArchivePath {
		return out, ErrVaultFileGenesisRecovery
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

	// The archive read and KDF are outside Session.mu so Lock can revoke an
	// operation waiting on disk. The opened bytes must match the independent
	// kit SHA and pass the signed backup/custody checks in decodeArchive.
	archived, err := decodeArchive(req.ArchivePath, string(password), key, string(recoveryMaterial))
	if err != nil {
		return out, fmt.Errorf("%w: archive", ErrVaultFileGenesisRecovery)
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
		return out, fmt.Errorf("%w: archive custody", ErrVaultFileGenesisRecovery)
	}

	intent, intentExists, err := loadVaultFileGenesisIntent(req.IntentPath)
	if err != nil {
		if errors.Is(err, vaultfilejournal.ErrUnsupported) {
			return out, err
		}
		return out, ErrVaultFileGenesisIntent
	}
	defer func() { clear(intent.SealedBytes) }()
	material, err := s.loadVaultFileGenesisMaterial(req.VaultID, *archivedOwner)
	if err != nil {
		return out, fmt.Errorf("%w: current custody", err)
	}
	defer material.clear()
	root := ed25519.NewKeyFromSeed(material.owner.OwnerRootSeed)
	rootPin := &vaultfile.GenesisRootPin{VaultID: req.VaultID,
		OwnerRootKeyID:     material.owner.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(root.Public().(ed25519.PublicKey))}
	clear(root)
	if !intentExists {
		intent, err = sealVaultFileGenesis(req.Name, material.owner, material.localSigning, material.localRecipient, rootPin)
		if err != nil {
			return out, fmt.Errorf("%w: seal", ErrVaultFileGenesisRecovery)
		}
	}
	checkpoint, err := verifyVaultFileGenesisIntent(req, intent, material.owner, material.localSigning, material.localAgeIdentity, material.localRecipient, rootPin)
	if err != nil {
		if intentExists {
			return out, ErrVaultFileGenesisIntent
		}
		return out, fmt.Errorf("%w: open", ErrVaultFileGenesisRecovery)
	}
	out = VaultFileGenesisPublic{Ownership: material.projection, PolicyDigest: hex.EncodeToString(checkpoint.PolicyDigest)}

	// A retry checks the pathname again after the expensive cryptography. It
	// cannot silently accept a different intent installed during this call.
	if intentExists {
		current, exists, err := loadVaultFileGenesisIntent(req.IntentPath)
		defer clear(current.SealedBytes)
		if err != nil || !exists || !sameVaultFileGenesisIntent(current, intent) {
			return VaultFileGenesisPublic{}, ErrVaultFileGenesisIntent
		}
	}
	// Reauthenticate the complete selected private custody record at the
	// final gate. RequestLock shares saveMu with commit-start and completion;
	// neither Session.mu nor saveMu is held across journal fsync.
	s.mu.Lock()
	rechecked, err := s.loadVaultFileGenesisMaterialLocked(req.VaultID, *archivedOwner)
	rechecked.clear()
	if err != nil {
		s.mu.Unlock()
		return VaultFileGenesisPublic{}, err
	}
	s.saveMu.Lock()
	if s.lockRequested.Load() || len(s.material) == 0 || s.idleExpired(time.Now()) || s.requireFreshFullFactor() != nil {
		s.saveMu.Unlock()
		s.mu.Unlock()
		return VaultFileGenesisPublic{}, ErrVaultFileFullFactorRequired
	}
	if intentExists {
		s.saveMu.Unlock()
		s.mu.Unlock()
		return out, nil
	}
	// Releasing these short locks marks commit-start. A later RequestLock
	// wins before completion and makes even a successful create UNKNOWN.
	s.saveMu.Unlock()
	s.mu.Unlock()
	createErr := vaultfilejournal.CreateNewGenesisIntent(req.IntentPath, intent)
	s.mu.Lock()
	activeErr := s.active(false)
	s.saveMu.Lock()
	cancelled := activeErr != nil || s.lockRequested.Load() || len(s.material) == 0 ||
		s.idleExpired(time.Now()) || s.requireFreshFullFactor() != nil
	s.saveMu.Unlock()
	s.mu.Unlock()
	if cancelled || errors.Is(createErr, vaultfilejournal.ErrCreateUnknown) {
		return VaultFileGenesisPublic{}, ErrVaultFileGenesisUnknown
	}
	if createErr != nil {
		if errors.Is(createErr, vaultfilejournal.ErrUnsupported) {
			return VaultFileGenesisPublic{}, createErr
		}
		return VaultFileGenesisPublic{}, ErrVaultFileGenesisIntent
	}
	return out, nil
}

type vaultFileGenesisMaterial struct {
	owner            vaultFileOwnerRecord
	localSigning     []byte
	localAgeIdentity []byte
	localRecipient   string
	projection       VaultFileOwnershipPublic
}

func (m *vaultFileGenesisMaterial) clear() {
	clearVaultFileOwners([]vaultFileOwnerRecord{m.owner})
	clear(m.localSigning)
	clear(m.localAgeIdentity)
	*m = vaultFileGenesisMaterial{}
}

func (s *Session) loadVaultFileGenesisMaterial(vaultID string, archived vaultFileOwnerRecord) (vaultFileGenesisMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadVaultFileGenesisMaterialLocked(vaultID, archived)
}

// The caller holds Session.mu. It is run again at commit-start so a local
// custody change during sealing cannot be turned into a durable intent.
func (s *Session) loadVaultFileGenesisMaterialLocked(vaultID string, archived vaultFileOwnerRecord) (vaultFileGenesisMaterial, error) {
	var material vaultFileGenesisMaterial
	if err := s.active(false); err != nil {
		return material, err
	}
	if s.requireFreshFullFactor() != nil {
		return material, ErrVaultFileFullFactorRequired
	}
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return material, err
	}
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerListAction, s, false)
		if err != nil {
			return err
		}
		defer auth.clear()
		records, err := loadVaultFileOwners(tx.Bucket(bucket), auth.identity, auth.rows)
		if err != nil {
			return err
		}
		defer clearVaultFileOwners(records)
		for i := range records {
			if records[i].VaultID != vaultID {
				continue
			}
			if !sameVaultFileGenesisOwner(records[i], archived) {
				return ErrVaultFileGenesisRecovery
			}
			device, err := age.ParseX25519Identity(auth.identity.Device)
			if err != nil {
				return invalid
			}
			material.owner = cloneVaultFileOwners(records[i : i+1])[0]
			material.localSigning = bytes.Clone(auth.identity.Signing)
			material.localAgeIdentity = []byte(auth.identity.Device)
			material.localRecipient = device.Recipient().String()
			material.projection, err = vaultFileOwnerPublic(records[i])
			return err
		}
		return ErrVaultFileGenesisRecovery
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		material.clear()
		return vaultFileGenesisMaterial{}, ErrVaultFileGenesisRecovery
	}
	if closeErr != nil {
		material.clear()
		return vaultFileGenesisMaterial{}, ErrCommandClose
	}
	if err := s.active(false); err != nil {
		material.clear()
		return vaultFileGenesisMaterial{}, err
	}
	if s.requireFreshFullFactor() != nil {
		material.clear()
		return vaultFileGenesisMaterial{}, ErrVaultFileFullFactorRequired
	}
	return material, nil
}

func loadVaultFileGenesisIntent(path string) (vaultfilejournal.GenesisIntent, bool, error) {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return vaultfilejournal.GenesisIntent{}, false, nil
	} else if err != nil {
		return vaultfilejournal.GenesisIntent{}, false, err
	}
	journal, err := vaultfilejournal.OpenExistingIntent(path)
	if err != nil {
		return vaultfilejournal.GenesisIntent{}, false, err
	}
	intent, err := journal.Load()
	closeErr := journal.Close()
	if err != nil || closeErr != nil {
		clear(intent.SealedBytes)
		return vaultfilejournal.GenesisIntent{}, false, ErrVaultFileGenesisIntent
	}
	return intent, true, nil
}

func sameVaultFileGenesisIntent(a, b vaultfilejournal.GenesisIntent) bool {
	return a.Name == b.Name && a.VaultID == b.VaultID && a.OwnerRootKeyID == b.OwnerRootKeyID &&
		a.PolicySeq == b.PolicySeq && a.OperationID == b.OperationID &&
		bytes.Equal(a.OwnerRootPublicKey, b.OwnerRootPublicKey) &&
		bytes.Equal(a.PolicyDigest, b.PolicyDigest) && bytes.Equal(a.SealedBytes, b.SealedBytes)
}

func validVaultFileGenesisPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func sameVaultFileGenesisOwner(a, b vaultFileOwnerRecord) bool {
	return a.VaultID == b.VaultID && a.OwnerRootKeyID == b.OwnerRootKeyID &&
		a.RecoveryDeviceID == b.RecoveryDeviceID &&
		bytes.Equal(a.OwnerRootSeed, b.OwnerRootSeed) &&
		bytes.Equal(a.RecoverySigningSeed, b.RecoverySigningSeed) &&
		bytes.Equal(a.RecoveryAgeIdentity, b.RecoveryAgeIdentity)
}

func sealVaultFileGenesis(name string, owner vaultFileOwnerRecord, localSigningSeed []byte, localRecipient string, rootPin *vaultfile.GenesisRootPin) (vaultfilejournal.GenesisIntent, error) {
	var intent vaultfilejournal.GenesisIntent
	policy, err := vaultFileGenesisExpectedPolicy(owner, localSigningSeed, localRecipient, rootPin)
	if err != nil {
		return intent, err
	}
	localSigner := ed25519.NewKeyFromSeed(localSigningSeed)
	rootSigner := ed25519.NewKeyFromSeed(owner.OwnerRootSeed)
	defer clear(localSigner)
	defer clear(rootSigner)
	return sealVaultFileGenesisPolicy(name, owner, policy, localSigner, rootSigner, rootPin)
}

const vaultFileGenesisAuthorDeviceID = "personal-owner-device"

// This is the complete roster this producer can author. A root-valid file
// with different local identity or additional roles is not its retry.
func vaultFileGenesisExpectedPolicy(owner vaultFileOwnerRecord, localSigningSeed []byte, localRecipient string, rootPin *vaultfile.GenesisRootPin) (*vaultfile.Policy, error) {
	if len(localSigningSeed) != ed25519.SeedSize || rootPin == nil {
		return nil, ErrVaultFileGenesisRecovery
	}
	recoveryAge, err := age.ParseX25519Identity(string(owner.RecoveryAgeIdentity))
	if err != nil {
		return nil, err
	}
	localSigner := ed25519.NewKeyFromSeed(localSigningSeed)
	recoverySigner := ed25519.NewKeyFromSeed(owner.RecoverySigningSeed)
	defer clear(localSigner)
	defer clear(recoverySigner)
	policy := &vaultfile.Policy{Format: vaultfile.Format, Version: vaultfile.Version,
		VaultID: owner.VaultID, PolicySeq: 0,
		OwnerRoot: vaultfile.OwnerRoot{KeyID: owner.OwnerRootKeyID, Alg: vaultfile.PolicySigAlgEd25519,
			PublicKey: bytes.Clone(rootPin.OwnerRootPublicKey),
			Owners:    []vaultfile.Principal{{PrincipalID: "owner", Label: "Owner"}}},
		Writers: []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}, {PrincipalID: "recovery", Label: "Recovery"}},
		Owners:  []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}},
		Devices: []vaultfile.Device{
			{DeviceID: vaultFileGenesisAuthorDeviceID, PrincipalID: "owner", Label: "Personal device",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(localSigner.Public().(ed25519.PublicKey))},
				AgeEncryptionKey:  localRecipient},
			{DeviceID: owner.RecoveryDeviceID, PrincipalID: "recovery", Label: "Recovery device",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(recoverySigner.Public().(ed25519.PublicKey))},
				AgeEncryptionKey:  recoveryAge.Recipient().String()},
		},
	}
	sort.Slice(policy.Devices, func(i, j int) bool { return policy.Devices[i].DeviceID < policy.Devices[j].DeviceID })
	if err := vaultfile.ValidatePolicy(policy); err != nil {
		return nil, err
	}
	return policy, nil
}

func sealVaultFileGenesisPolicy(name string, owner vaultFileOwnerRecord, policy *vaultfile.Policy, localSigner, rootSigner ed25519.PrivateKey, rootPin *vaultfile.GenesisRootPin) (vaultfilejournal.GenesisIntent, error) {
	var intent vaultfilejournal.GenesisIntent
	document, err := vaultfile.EncodePolicyDocument(policy)
	if err != nil {
		return intent, err
	}
	proof := vaultfile.SignedPolicy{Policy: *policy, Document: document,
		SignerID: owner.OwnerRootKeyID, Alg: vaultfile.PolicySigAlgEd25519,
		Sig: ed25519.Sign(rootSigner, append([]byte(vaultfile.DomainPolicyDocumentSignature+"\x00"), document...))}
	operationID, err := randomID()
	if err != nil {
		return intent, err
	}
	policyDigest := vaultfile.PolicyDigest(policy)
	checkpoint := &vaultfile.PolicyCheckpoint{VaultID: owner.VaultID, OwnerRootKeyID: owner.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(rootPin.OwnerRootPublicKey), PolicySeq: 0, PolicyDigest: policyDigest}
	draft := &vaultfile.File{Format: vaultfile.Format, Version: vaultfile.Version,
		Header: vaultfile.Header{VaultID: owner.VaultID, KeyEpoch: 1, ContentSeq: 0,
			OpID: operationID, PolicySeq: 0, PolicyDigest: policyDigest, AuthorDeviceID: vaultFileGenesisAuthorDeviceID},
		SignedPolicyProofs: []vaultfile.SignedPolicy{proof}}
	vuk := make([]byte, vaultfile.CEKSize)
	defer clear(vuk)
	if _, err := rand.Read(vuk); err != nil {
		return intent, err
	}
	sealed, err := vault.SealAuthenticatedItems(draft, []byte{}, []vault.Item{}, checkpoint, vuk, localSigner)
	if err != nil {
		return intent, err
	}
	intent = vaultfilejournal.GenesisIntent{Name: name, VaultID: owner.VaultID,
		OwnerRootKeyID: owner.OwnerRootKeyID, OwnerRootPublicKey: bytes.Clone(rootPin.OwnerRootPublicKey),
		PolicySeq: 0, PolicyDigest: bytes.Clone(policyDigest), OperationID: operationID, SealedBytes: sealed}
	return intent, nil
}

func verifyVaultFileGenesisIntent(req VaultFileGenesisRequest, intent vaultfilejournal.GenesisIntent, owner vaultFileOwnerRecord, localSigningSeed, localAgeIdentity []byte, localRecipient string, pin *vaultfile.GenesisRootPin) (*vaultfile.PolicyCheckpoint, error) {
	if intent.Name != req.Name || intent.VaultID != req.VaultID || intent.OwnerRootKeyID != pin.OwnerRootKeyID ||
		!bytes.Equal(intent.OwnerRootPublicKey, pin.OwnerRootPublicKey) || intent.PolicySeq != 0 {
		return nil, ErrVaultFileGenesisIntent
	}
	checkpoint, err := vaultfile.VerifyGenesis(intent.SealedBytes, pin)
	if err != nil || checkpoint == nil || !bytes.Equal(intent.PolicyDigest, checkpoint.PolicyDigest) {
		return nil, ErrVaultFileGenesisIntent
	}
	f, err := vaultfile.ParseFile(intent.SealedBytes)
	if err != nil || f.Header.OpID != intent.OperationID || f.Header.AuthorDeviceID != vaultFileGenesisAuthorDeviceID {
		return nil, ErrVaultFileGenesisIntent
	}
	expected, err := vaultFileGenesisExpectedPolicy(owner, localSigningSeed, localRecipient, pin)
	if err != nil {
		return nil, ErrVaultFileGenesisIntent
	}
	document, err := vaultfile.EncodePolicyDocument(expected)
	if err != nil || !bytes.Equal(f.SignedPolicyProofs[0].Document, document) ||
		!bytes.Equal(checkpoint.PolicyDigest, vaultfile.PolicyDigest(expected)) ||
		len(f.VUKDeviceSlots) != len(expected.Devices) {
		return nil, ErrVaultFileGenesisIntent
	}
	for i := range expected.Devices {
		if f.VUKDeviceSlots[i].DeviceID != expected.Devices[i].DeviceID ||
			f.VUKDeviceSlots[i].Recipient != expected.Devices[i].AgeEncryptionKey {
			return nil, ErrVaultFileGenesisIntent
		}
	}
	localAge, err := age.ParseX25519Identity(string(localAgeIdentity))
	if err != nil || localAge.Recipient().String() != localRecipient {
		return nil, ErrVaultFileGenesisIntent
	}
	_, localMetadata, localItems, err := vault.OpenAuthenticatedItems(intent.SealedBytes, checkpoint, vaultFileGenesisAuthorDeviceID, localAge)
	defer clear(localMetadata)
	defer clearAuthenticatedItems(localItems)
	if err != nil || len(localMetadata) != 0 || len(localItems) != 0 {
		return nil, ErrVaultFileGenesisRecovery
	}
	recoverySigner := ed25519.NewKeyFromSeed(owner.RecoverySigningSeed)
	defer clear(recoverySigner)
	var recovery *vaultfile.Device
	for i := range f.SignedPolicyProofs[0].Policy.Devices {
		device := &f.SignedPolicyProofs[0].Policy.Devices[i]
		if device.DeviceID == owner.RecoveryDeviceID {
			recovery = device
			break
		}
	}
	recoveryAge, err := age.ParseX25519Identity(string(owner.RecoveryAgeIdentity))
	if err != nil || recovery == nil || recovery.ContentSigningKey.Alg != vaultfile.SigAlgEd25519 ||
		!bytes.Equal(recovery.ContentSigningKey.PublicKey, recoverySigner.Public().(ed25519.PublicKey)) ||
		recovery.AgeEncryptionKey != recoveryAge.Recipient().String() {
		return nil, ErrVaultFileGenesisRecovery
	}
	writer := false
	for _, member := range f.SignedPolicyProofs[0].Policy.Writers {
		writer = writer || member.PrincipalID == recovery.PrincipalID
	}
	if !writer {
		return nil, ErrVaultFileGenesisRecovery
	}
	_, metadata, items, err := vault.OpenAuthenticatedItems(intent.SealedBytes, checkpoint, owner.RecoveryDeviceID, recoveryAge)
	defer clear(metadata)
	defer clearAuthenticatedItems(items)
	if err != nil || len(metadata) != 0 || len(items) != 0 {
		return nil, ErrVaultFileGenesisRecovery
	}
	return checkpoint, nil
}
