//go:build darwin || linux

package personal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

type managedDeviceSuccessorFixture struct {
	*ownerRecoveryImportFixture

	base           []byte
	baseRevision   vaultfilebackend.Revision
	pin            VaultFileManagedDeviceSuccessorPin
	destinationAge *age.X25519Identity
	recoveryDevice string
	recoveryOwner  string
}

func readManagedDeviceSuccessorBase(t *testing.T,
	target VaultFileManagedDeviceSuccessorTarget) ([]byte, vaultfilebackend.Revision) {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(target.Root)
	if err != nil {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_BACKEND_OPEN_FAILED")
	}
	result, readErr := backend.Read(context.Background(), target.Name)
	closeErr := backend.Close()
	if readErr != nil || closeErr != nil {
		clear(result.Bytes)
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_TARGET_READ_FAILED")
	}
	if len(result.Bytes) == 0 || result.Revision.Zero() {
		clear(result.Bytes)
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_TARGET_SHAPE_FAILED")
	}
	return result.Bytes, result.Revision
}

func newManagedDeviceSuccessorPin(t *testing.T, expected vaultfile.PolicyCheckpoint,
	base []byte, revision vaultfilebackend.Revision) VaultFileManagedDeviceSuccessorPin {
	t.Helper()
	parsed, err := vaultfile.ParseFile(base)
	if err != nil {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_BASE_PARSE_FAILED")
	}
	return VaultFileManagedDeviceSuccessorPin{
		Checkpoint:      cloneVaultFileCheckpoint(&expected),
		KeyEpoch:        parsed.Header.KeyEpoch,
		ContentSeq:      parsed.Header.ContentSeq,
		SealedSHA256:    sha256.Sum256(base),
		BackendRevision: revision,
	}
}

func newManagedDeviceSuccessorFixture(t *testing.T, label string) *managedDeviceSuccessorFixture {
	t.Helper()
	return newManagedDeviceSuccessorFixtureFromSource(t, label, loadOwnerRecoveryImportSource(t))
}

func newManagedDeviceSuccessorFixtureFromSource(t *testing.T, label string,
	source *ownerRecoveryImportSourceFixture) *managedDeviceSuccessorFixture {
	t.Helper()
	restored := newOwnerRecoveryImportFixtureFromSource(t, label, source)
	if _, err := restored.destSession.RestoreVaultFileBackupCustodyOwner(context.Background(),
		restored.artifact, restored.expected, restored.factor, restored.binding,
		restored.target); err != nil {
		t.Fatalf("MANAGED_DEVICE_SUCCESSOR_IMPORT_FAILED: %v", err)
	}
	base, revision := readManagedDeviceSuccessorBase(t, restored.target)
	pin := newManagedDeviceSuccessorPin(t, restored.expected, base, revision)
	parsed, err := vaultfile.ParseFile(base)
	if err != nil || len(parsed.SignedPolicyProofs) == 0 {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_BASE_POLICY_FAILED")
	}
	basePolicy := &parsed.SignedPolicyProofs[len(parsed.SignedPolicyProofs)-1].Policy
	public, err := vaultFileOwnerPublic(restored.owner)
	if err != nil {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_OWNER_PUBLIC_FAILED")
	}
	recoverySigning, err := hex.DecodeString(public.RecoveryContentSigningPublicKey)
	if err != nil || len(recoverySigning) != ed25519.PublicKeySize {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_RECOVERY_PUBLIC_FAILED")
	}
	recoveryDevice, ok := localVaultFileWriterDevice(basePolicy,
		public.RecoveryAgeRecipient, recoverySigning)
	if !ok || recoveryDevice != restored.owner.RecoveryDeviceID {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_RECOVERY_DEVICE_FAILED")
	}
	recoveryOwner, ok := ownedVaultFileDevicePrincipal(basePolicy, recoveryDevice)
	if !ok {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_RECOVERY_PRINCIPAL_FAILED")
	}
	signer, destinationAge, recipient := ownedSuccessorLocalIdentity(t, restored.destSession)
	clear(signer)
	if recipient != restored.destDevice.AgeRecipient {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_DESTINATION_IDENTITY_FAILED")
	}
	f := &managedDeviceSuccessorFixture{
		ownerRecoveryImportFixture: restored,
		base:                       base,
		baseRevision:               revision,
		pin:                        pin,
		destinationAge:             destinationAge,
		recoveryDevice:             recoveryDevice,
		recoveryOwner:              recoveryOwner,
	}
	t.Cleanup(f.clear)
	return f
}

func (f *managedDeviceSuccessorFixture) clear() {
	if f == nil {
		return
	}
	clear(f.base)
	clearVaultFilePolicyCheckpoint(&f.pin.Checkpoint)
	f.destinationAge = nil
	*f = managedDeviceSuccessorFixture{}
}

func sameVaultFileManagedDevice(a, b vaultfile.Device) bool {
	if a.DeviceID != b.DeviceID || a.PrincipalID != b.PrincipalID || a.Label != b.Label ||
		a.AgeEncryptionKey != b.AgeEncryptionKey ||
		a.ContentSigningKey.Alg != b.ContentSigningKey.Alg ||
		!bytes.Equal(a.ContentSigningKey.PublicKey, b.ContentSigningKey.PublicKey) {
		return false
	}
	if (a.PolicySigningKey == nil) != (b.PolicySigningKey == nil) {
		return false
	}
	if a.PolicySigningKey != nil &&
		(a.PolicySigningKey.Alg != b.PolicySigningKey.Alg ||
			!bytes.Equal(a.PolicySigningKey.PublicKey, b.PolicySigningKey.PublicKey)) {
		return false
	}
	return true
}

func cloneManagedDeviceSuccessorPin(pin VaultFileManagedDeviceSuccessorPin) VaultFileManagedDeviceSuccessorPin {
	pin.Checkpoint = cloneVaultFileCheckpoint(&pin.Checkpoint)
	return pin
}

func assertZeroManagedDeviceSuccessor(t *testing.T, out VaultFileManagedDeviceSuccessor) {
	t.Helper()
	if len(out.Draft) != 0 || out.Base.Checkpoint.VaultID != "" ||
		out.Base.KeyEpoch != 0 || out.Base.ContentSeq != 0 ||
		out.Base.BackendRevision != "" || out.Next.Checkpoint.VaultID != "" {
		out.Clear()
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_RETURNED_PARTIAL_OUTPUT")
	}
}

func assertManagedDeviceSuccessorTargetUnchanged(t *testing.T, f *managedDeviceSuccessorFixture) {
	t.Helper()
	after, revision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(after)
	if !bytes.Equal(after, f.base) || revision != f.baseRevision {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_TARGET_CHANGED")
	}
}

func TestVaultFileManagedDeviceSuccessorPreparesOnlyNewDevice(t *testing.T) {
	f := newManagedDeviceSuccessorFixture(t, "managed-successor")
	baseFile, err := vaultfile.ParseFile(f.base)
	if err != nil || len(baseFile.SignedPolicyProofs) == 0 {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_BASE_PARSE_FAILED")
	}
	basePolicy := &baseFile.SignedPolicyProofs[len(baseFile.SignedPolicyProofs)-1].Policy
	destinationSigning, err := hex.DecodeString(f.destDevice.ContentSigningPublicKey)
	if err != nil || len(destinationSigning) != ed25519.PublicKeySize {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_DESTINATION_PUBLIC_FAILED")
	}
	if _, ok := localVaultFileReaderDevice(basePolicy,
		f.destDevice.AgeRecipient, destinationSigning); ok {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_DESTINATION_ALREADY_ENROLLED")
	}
	epochBefore, countBefore := ownerRecoveryState(t, f.destSession, f.destPath)
	deviceBefore, err := f.destSession.VaultFileDevicePublic()
	if err != nil {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_DESTINATION_READ_FAILED")
	}

	out, err := f.destSession.PrepareVaultFileManagedDeviceSuccessor(context.Background(),
		f.target, f.pin)
	if err != nil {
		t.Fatalf("MANAGED_DEVICE_SUCCESSOR_PREPARE_FAILED: %v", err)
	}
	defer out.Clear()
	if len(out.Draft) == 0 || len(out.Draft) > vaultfile.MaxFileBytes {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_DRAFT_BOUND_FAILED")
	}
	if sha256.Sum256(out.Draft) == f.pin.SealedSHA256 {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_DRAFT_REUSED_BASE")
	}
	if !sameVaultFileBackupCustodyCheckpoint(out.Base.Checkpoint, f.pin.Checkpoint) ||
		out.Base.KeyEpoch != f.pin.KeyEpoch || out.Base.ContentSeq != f.pin.ContentSeq ||
		out.Base.SealedSHA256 != f.pin.SealedSHA256 ||
		out.Base.BackendRevision != f.pin.BackendRevision {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_BASE_PIN_CHANGED")
	}
	if out.Next.Checkpoint.PolicySeq != f.pin.Checkpoint.PolicySeq+1 ||
		out.Next.KeyEpoch != f.pin.KeyEpoch+1 ||
		out.Next.ContentSeq != f.pin.ContentSeq+1 {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_NEXT_PIN_CHANGED")
	}
	if err := vaultfile.VerifyManagedTransition(f.base, out.Draft, &f.pin.Checkpoint); err != nil {
		t.Fatalf("MANAGED_DEVICE_SUCCESSOR_TRANSITION_FAILED: %v", err)
	}
	sealed, err := vaultfile.ParseFile(out.Draft)
	if err != nil || len(sealed.SignedPolicyProofs) == 0 {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_DRAFT_PARSE_FAILED")
	}
	if err := vaultfile.VerifyPolicyCheckpoint(sealed, &out.Next.Checkpoint); err != nil {
		t.Fatalf("MANAGED_DEVICE_SUCCESSOR_NEXT_VERIFY_FAILED: %v", err)
	}
	if !bytes.Equal(out.Next.Checkpoint.PolicyDigest, sealed.Header.PolicyDigest) ||
		sealed.Header.AuthorDeviceID != f.recoveryDevice {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_NEXT_BINDING_FAILED")
	}
	nextPolicy := &sealed.SignedPolicyProofs[len(sealed.SignedPolicyProofs)-1].Policy
	if !sameVaultFileManagedDeviceAuthority(basePolicy, nextPolicy) {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_AUTHORITY_CHANGED")
	}
	if len(nextPolicy.Devices) != len(basePolicy.Devices)+1 {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_DEVICE_COUNT_CHANGED")
	}
	for _, oldDevice := range basePolicy.Devices {
		found := false
		for i := range nextPolicy.Devices {
			if sameVaultFileManagedDevice(oldDevice, nextPolicy.Devices[i]) {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("MANAGED_DEVICE_SUCCESSOR_OLD_DEVICE_CHANGED")
		}
	}
	var enrolled *vaultfile.Device
	for i := range nextPolicy.Devices {
		device := &nextPolicy.Devices[i]
		if device.AgeEncryptionKey == f.destDevice.AgeRecipient &&
			bytes.Equal(device.ContentSigningKey.PublicKey, destinationSigning) {
			enrolled = device
			break
		}
	}
	if enrolled == nil || enrolled.PrincipalID != f.recoveryOwner ||
		enrolled.PolicySigningKey != nil ||
		enrolled.ContentSigningKey.Alg != vaultfile.SigAlgEd25519 {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_DESTINATION_ENTRY_INVALID")
	}

	if _, db, err := vaultfile.OpenAuthenticatedFile(out.Draft, &out.Next.Checkpoint,
		enrolled.DeviceID, f.destinationAge); err != nil || db == nil {
		t.Fatalf("MANAGED_DEVICE_SUCCESSOR_DESTINATION_OPEN_FAILED: %v", err)
	}
	recoveryAge, err := age.ParseX25519Identity(string(f.owner.RecoveryAgeIdentity))
	if err != nil {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_RECOVERY_IDENTITY_FAILED")
	}
	if _, db, err := vaultfile.OpenAuthenticatedFile(out.Draft, &out.Next.Checkpoint,
		f.recoveryDevice, recoveryAge); err != nil || db == nil {
		t.Fatalf("MANAGED_DEVICE_SUCCESSOR_RECOVERY_OPEN_FAILED: %v", err)
	}

	if epochAfter, countAfter := ownerRecoveryState(t, f.destSession, f.destPath); epochAfter != epochBefore ||
		countAfter != countBefore {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_ACCOUNT_MUTATED")
	}
	if deviceAfter, err := f.destSession.VaultFileDevicePublic(); err != nil ||
		deviceAfter != deviceBefore {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_DESTINATION_DEVICE_CHANGED")
	}
	assertManagedDeviceSuccessorTargetUnchanged(t, f)
}

func TestVaultFileManagedDeviceSuccessorRejectsForeignPin(t *testing.T) {
	f := newManagedDeviceSuccessorFixture(t, "managed-foreign-pin")
	cases := []struct {
		name   string
		mutate func(*VaultFileManagedDeviceSuccessorPin)
	}{
		{"foreign-vault", func(pin *VaultFileManagedDeviceSuccessorPin) {
			pin.Checkpoint.VaultID = "ffffffffffffffffffffffffffffffff"
		}},
		{"foreign-root", func(pin *VaultFileManagedDeviceSuccessorPin) {
			pin.Checkpoint.OwnerRootKeyID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		}},
		{"wrong-policy-seq", func(pin *VaultFileManagedDeviceSuccessorPin) {
			pin.Checkpoint.PolicySeq++
		}},
		{"changed-revision", func(pin *VaultFileManagedDeviceSuccessorPin) {
			pin.BackendRevision += "-changed"
		}},
		{"wrong-epoch", func(pin *VaultFileManagedDeviceSuccessorPin) {
			pin.KeyEpoch++
		}},
		{"wrong-content-seq", func(pin *VaultFileManagedDeviceSuccessorPin) {
			pin.ContentSeq++
		}},
		{"wrong-digest", func(pin *VaultFileManagedDeviceSuccessorPin) {
			pin.SealedSHA256[0] ^= 0xff
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pin := cloneManagedDeviceSuccessorPin(f.pin)
			tc.mutate(&pin)
			out, err := f.destSession.PrepareVaultFileManagedDeviceSuccessor(
				context.Background(), f.target, pin)
			clearVaultFilePolicyCheckpoint(&pin.Checkpoint)
			if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessor) {
				out.Clear()
				t.Fatalf("MANAGED_DEVICE_SUCCESSOR_FOREIGN_PIN_ACCEPTED: %v", err)
			}
			assertZeroManagedDeviceSuccessor(t, out)
		})
	}
	assertManagedDeviceSuccessorTargetUnchanged(t, f)
}

func TestVaultFileManagedDeviceSuccessorRequiresRestoredOwner(t *testing.T) {
	f := newOwnerRecoveryImportFixture(t, "managed-no-owner")
	base, revision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(base)
	pin := newManagedDeviceSuccessorPin(t, f.expected, base, revision)
	defer clearVaultFilePolicyCheckpoint(&pin.Checkpoint)
	out, err := f.destSession.PrepareVaultFileManagedDeviceSuccessor(context.Background(),
		f.target, pin)
	if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessor) {
		out.Clear()
		t.Fatalf("MANAGED_DEVICE_SUCCESSOR_MISSING_OWNER_ACCEPTED: %v", err)
	}
	assertZeroManagedDeviceSuccessor(t, out)
	if after, afterRevision := readManagedDeviceSuccessorBase(t, f.target); !bytes.Equal(after, base) ||
		afterRevision != revision {
		clear(after)
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_MISSING_OWNER_MUTATED_TARGET")
	} else {
		clear(after)
	}
}

func TestVaultFileManagedDeviceSuccessorDoesNotCreateMissingTarget(t *testing.T) {
	f := newManagedDeviceSuccessorFixture(t, "managed-missing-target")
	target := f.target
	target.Name = "missing-managed-successor"
	out, err := f.destSession.PrepareVaultFileManagedDeviceSuccessor(context.Background(),
		target, f.pin)
	if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessor) {
		out.Clear()
		t.Fatalf("MANAGED_DEVICE_SUCCESSOR_MISSING_TARGET_ACCEPTED: %v", err)
	}
	assertZeroManagedDeviceSuccessor(t, out)
	backend, err := vaultfilebackend.OpenExistingDir(target.Root)
	if err != nil {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_MISSING_TARGET_OPEN_FAILED")
	}
	_, readErr := backend.Read(context.Background(), target.Name)
	closeErr := backend.Close()
	if !errors.Is(readErr, vaultfilebackend.ErrNotFound) || closeErr != nil {
		t.Fatal("MANAGED_DEVICE_SUCCESSOR_CREATED_MISSING_TARGET")
	}
	assertManagedDeviceSuccessorTargetUnchanged(t, f)
}

func TestVaultFileManagedDeviceSuccessorNoLateLockOrCancelResult(t *testing.T) {
	t.Run("locked-before", func(t *testing.T) {
		f := newManagedDeviceSuccessorFixture(t, "managed-locked")
		f.destSession.RequestLock()
		out, err := f.destSession.PrepareVaultFileManagedDeviceSuccessor(context.Background(),
			f.target, f.pin)
		if !errors.Is(err, ErrSessionLocked) {
			out.Clear()
			t.Fatalf("MANAGED_DEVICE_SUCCESSOR_LOCK_ACCEPTED: %v", err)
		}
		assertZeroManagedDeviceSuccessor(t, out)
		assertManagedDeviceSuccessorTargetUnchanged(t, f)
	})
	t.Run("canceled-before", func(t *testing.T) {
		f := newManagedDeviceSuccessorFixture(t, "managed-canceled")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out, err := f.destSession.PrepareVaultFileManagedDeviceSuccessor(ctx, f.target, f.pin)
		if !errors.Is(err, context.Canceled) {
			out.Clear()
			t.Fatalf("MANAGED_DEVICE_SUCCESSOR_CANCEL_ACCEPTED: %v", err)
		}
		assertZeroManagedDeviceSuccessor(t, out)
		assertManagedDeviceSuccessorTargetUnchanged(t, f)
	})
	t.Run("late-lock", func(t *testing.T) {
		f := newManagedDeviceSuccessorFixture(t, "managed-late-lock")
		vaultFileManagedDeviceSuccessorBeforeReleaseForTest = func() {
			f.destSession.RequestLock()
		}
		defer func() { vaultFileManagedDeviceSuccessorBeforeReleaseForTest = nil }()
		out, err := f.destSession.PrepareVaultFileManagedDeviceSuccessor(context.Background(),
			f.target, f.pin)
		if !errors.Is(err, ErrSessionLocked) {
			out.Clear()
			t.Fatalf("MANAGED_DEVICE_SUCCESSOR_LATE_LOCK_ACCEPTED: %v", err)
		}
		assertZeroManagedDeviceSuccessor(t, out)
		assertManagedDeviceSuccessorTargetUnchanged(t, f)
	})
	t.Run("late-cancel", func(t *testing.T) {
		f := newManagedDeviceSuccessorFixture(t, "managed-late-cancel")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		vaultFileManagedDeviceSuccessorBeforeReleaseForTest = cancel
		defer func() { vaultFileManagedDeviceSuccessorBeforeReleaseForTest = nil }()
		out, err := f.destSession.PrepareVaultFileManagedDeviceSuccessor(ctx, f.target, f.pin)
		if !errors.Is(err, context.Canceled) {
			out.Clear()
			t.Fatalf("MANAGED_DEVICE_SUCCESSOR_LATE_CANCEL_ACCEPTED: %v", err)
		}
		assertZeroManagedDeviceSuccessor(t, out)
		assertManagedDeviceSuccessorTargetUnchanged(t, f)
	})
}
