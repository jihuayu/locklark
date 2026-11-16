//go:build darwin || linux

package vaultfilepublish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// A real SDK seal with independently generated root, author and recovery
// identities. The pin is captured from the generated root before G is built.
func genesisDirFixtureG(t *testing.T) (vaultfilejournal.GenesisIntent, *vaultfile.GenesisRootPin) {
	t.Helper()
	keypair := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("GENESIS_KEY_FIXTURE_FAILED")
		}
		return pub, priv
	}
	rootPub, rootPriv := keypair()
	authorPub, authorPriv := keypair()
	recoveryPub, _ := keypair()
	authorAge, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("GENESIS_AGE_FIXTURE_FAILED")
	}
	recoveryAge, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("GENESIS_RECOVERY_AGE_FIXTURE_FAILED")
	}
	pin := &vaultfile.GenesisRootPin{VaultID: "vault-genesis", OwnerRootKeyID: "root-genesis",
		OwnerRootPublicKey: bytes.Clone(rootPub)}
	policy := &vaultfile.Policy{Format: vaultfile.Format, Version: vaultfile.Version,
		VaultID: pin.VaultID, PolicySeq: 0,
		OwnerRoot: vaultfile.OwnerRoot{KeyID: pin.OwnerRootKeyID, Alg: vaultfile.PolicySigAlgEd25519,
			PublicKey: bytes.Clone(rootPub), Owners: []vaultfile.Principal{{PrincipalID: "owner", Label: "Owner"}}},
		Owners: []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}},
		Devices: []vaultfile.Device{
			{DeviceID: "device-author", PrincipalID: "owner", Label: "Author",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(authorPub)},
				AgeEncryptionKey:  authorAge.Recipient().String()},
			{DeviceID: "device-recovery", PrincipalID: "owner", Label: "Recovery",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(recoveryPub)},
				AgeEncryptionKey:  recoveryAge.Recipient().String()},
		},
	}
	document, err := vaultfile.EncodePolicyDocument(policy)
	if err != nil {
		t.Fatal("GENESIS_POLICY_DOCUMENT_FIXTURE_FAILED")
	}
	proof := vaultfile.SignedPolicy{Document: document, Policy: *policy,
		SignerID: pin.OwnerRootKeyID, Alg: vaultfile.PolicySigAlgEd25519,
		Sig: ed25519.Sign(rootPriv, append([]byte(vaultfile.DomainPolicyDocumentSignature+"\x00"), document...))}
	digest := vaultfile.PolicyDigest(policy)
	draft := &vaultfile.File{Format: vaultfile.Format, Version: vaultfile.Version,
		Header: vaultfile.Header{VaultID: pin.VaultID, OpID: "genesis-operation",
			AuthorDeviceID: "device-author", KeyEpoch: 1, PolicySeq: 0,
			PolicyDigest: bytes.Clone(digest), ContentSeq: 0},
		SignedPolicyProofs: []vaultfile.SignedPolicy{proof}}
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	group := kdbx.NewGroup()
	group.Name = "Fixture"
	entry := kdbx.NewEntry()
	entry.Values = []kdbx.ValueData{{Key: "Title", Value: kdbx.V{Content: "owned genesis item"}}}
	group.Entries = []kdbx.Entry{entry}
	db.Content.Root.Groups = []kdbx.Group{group}
	vuk := make([]byte, vaultfile.CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal("GENESIS_VUK_FIXTURE_FAILED")
	}
	cp := &vaultfile.PolicyCheckpoint{VaultID: pin.VaultID, OwnerRootKeyID: pin.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(rootPub), PolicySeq: 0, PolicyDigest: bytes.Clone(digest)}
	sealed, err := vaultfile.SealAuthenticatedFile(draft, db, cp, vuk, authorPriv)
	if err != nil {
		t.Fatal("GENESIS_REAL_SEAL_FIXTURE_FAILED")
	}
	intent := vaultfilejournal.GenesisIntent{Name: "vault-file", VaultID: pin.VaultID,
		OwnerRootKeyID: pin.OwnerRootKeyID, OwnerRootPublicKey: bytes.Clone(rootPub),
		PolicySeq: 0, PolicyDigest: bytes.Clone(digest), OperationID: draft.Header.OpID,
		SealedBytes: sealed}
	if _, err := vaultfile.VerifyGenesis(intent.SealedBytes, pin); err != nil {
		t.Fatal("GENESIS_INDEPENDENT_VERIFICATION_FIXTURE_FAILED")
	}
	return intent, pin
}

type genesisDirFixture struct {
	dir         *vaultfilebackend.Dir
	journal     *vaultfilejournal.IntentJournal
	journalPath string
	backendRoot string
	intent      vaultfilejournal.GenesisIntent
	pin         *vaultfile.GenesisRootPin
}

func newGenesisDirFixture(t *testing.T, mutate func(*vaultfilejournal.GenesisIntent)) *genesisDirFixture {
	t.Helper()
	intent, pin := genesisDirFixtureG(t)
	if mutate != nil {
		mutate(&intent)
	}
	parent := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal("GENESIS_JOURNAL_PARENT_FAILED")
	}
	journalPath := filepath.Join(parent, "intent.db")
	if err := vaultfilejournal.CreateNewGenesisIntent(journalPath, intent); err != nil {
		t.Fatal("GENESIS_INTENT_PERSIST_FAILED")
	}
	j, err := vaultfilejournal.OpenExistingIntent(journalPath)
	if err != nil {
		t.Fatal("GENESIS_INTENT_REOPEN_FAILED")
	}
	t.Cleanup(func() { _ = j.Close() })
	backendRoot := filepath.Join(t.TempDir(), "backend")
	dir, err := vaultfilebackend.OpenDir(backendRoot)
	if err != nil {
		t.Fatal("GENESIS_DIR_OPEN_FAILED")
	}
	t.Cleanup(func() { _ = dir.Close() })
	return &genesisDirFixture{dir: dir, journal: j, journalPath: journalPath,
		backendRoot: backendRoot, intent: intent, pin: pin}
}

func assertGenesisIntentPending(t *testing.T, f *genesisDirFixture) {
	t.Helper()
	if err := f.journal.Close(); err != nil {
		t.Fatal("GENESIS_INTENT_CLOSE_FAILED")
	}
	j, err := vaultfilejournal.OpenExistingIntent(f.journalPath)
	if err != nil {
		t.Fatal("GENESIS_PENDING_INTENT_LOST")
	}
	defer j.Close()
	got, err := j.Load()
	if err != nil || got.Name != f.intent.Name || got.VaultID != f.intent.VaultID ||
		got.OwnerRootKeyID != f.intent.OwnerRootKeyID ||
		!bytes.Equal(got.OwnerRootPublicKey, f.intent.OwnerRootPublicKey) ||
		got.PolicySeq != f.intent.PolicySeq || !bytes.Equal(got.PolicyDigest, f.intent.PolicyDigest) ||
		got.OperationID != f.intent.OperationID || !bytes.Equal(got.SealedBytes, f.intent.SealedBytes) {
		t.Fatal("GENESIS_PENDING_INTENT_CHANGED")
	}
}

func assertGenesisAcked(t *testing.T, f *genesisDirFixture, revision vaultfilebackend.Revision) {
	t.Helper()
	if err := f.journal.Close(); err != nil {
		t.Fatal("GENESIS_ACK_CLOSE_FAILED")
	}
	j, err := vaultfilejournal.OpenExisting(f.journalPath)
	if err != nil {
		t.Fatal("GENESIS_ACK_STATE_REOPEN_FAILED")
	}
	defer j.Close()
	state, err := j.LoadState()
	if err != nil || state.Generation != 0 || state.RemoteRevision != revision ||
		!bytes.Equal(state.BaseBytes, f.intent.SealedBytes) ||
		!bytes.Equal(state.WorkingBytes, f.intent.SealedBytes) {
		t.Fatal("GENESIS_ACK_STATE_MISMATCH")
	}
}

func TestPublishGenesisDirRealCreateReadAck(t *testing.T) {
	f := newGenesisDirFixture(t, nil)
	if err := PublishGenesisDir(context.Background(), f.dir, f.journal, f.pin); err != nil {
		t.Fatal("GENESIS_DIR_PUBLISH_FAILED")
	}
	remote, err := f.dir.Read(context.Background(), f.intent.Name)
	if err != nil || remote.Revision == "" || !bytes.Equal(remote.Bytes, f.intent.SealedBytes) {
		t.Fatal("GENESIS_DIR_REMOTE_MISMATCH")
	}
	assertGenesisAcked(t, f, remote.Revision)
}

func TestPublishGenesisDirExactCollisionAndLostResponseAck(t *testing.T) {
	for _, name := range []string{"exact-collision", "lost-create-response"} {
		t.Run(name, func(t *testing.T) {
			f := newGenesisDirFixture(t, nil)
			ctx := context.Background()
			if name == "exact-collision" {
				if err := f.dir.CreateIfAbsent(ctx, f.intent.Name, f.intent.SealedBytes); err != nil {
					t.Fatal("GENESIS_COLLISION_FIXTURE_FAILED")
				}
			}
			var err error
			if name == "lost-create-response" {
				err = publishGenesisDirWith(ctx, f.dir, f.journal, f.pin, func(actual error) {
					if actual != nil {
						t.Fatal("GENESIS_LOST_RESPONSE_CREATE_NOT_COMMITTED")
					}
				})
			} else {
				err = PublishGenesisDir(ctx, f.dir, f.journal, f.pin)
			}
			if err != nil {
				t.Fatal("GENESIS_EXACT_READBACK_NOT_ACKED")
			}
			remote, err := f.dir.Read(ctx, f.intent.Name)
			if err != nil || !bytes.Equal(remote.Bytes, f.intent.SealedBytes) {
				t.Fatal("GENESIS_EXACT_REMOTE_CHANGED")
			}
			assertGenesisAcked(t, f, remote.Revision)
		})
	}
}

func TestPublishGenesisDirForeignCollisionRetainsIntentAndRemote(t *testing.T) {
	f := newGenesisDirFixture(t, nil)
	foreign, _ := genesisDirFixtureG(t)
	ctx := context.Background()
	if err := f.dir.CreateIfAbsent(ctx, f.intent.Name, foreign.SealedBytes); err != nil {
		t.Fatal("GENESIS_FOREIGN_REMOTE_FIXTURE_FAILED")
	}
	before, err := f.dir.Read(ctx, f.intent.Name)
	if err != nil {
		t.Fatal("GENESIS_FOREIGN_REMOTE_READ_FAILED")
	}
	if err := PublishGenesisDir(ctx, f.dir, f.journal, f.pin); !errors.Is(err, ErrGenesisReview) {
		t.Fatal("GENESIS_FOREIGN_REMOTE_NOT_REVIEW")
	}
	after, err := f.dir.Read(ctx, f.intent.Name)
	if err != nil || after.Revision != before.Revision || !bytes.Equal(after.Bytes, before.Bytes) {
		t.Fatal("GENESIS_FOREIGN_REMOTE_CHANGED")
	}
	assertGenesisIntentPending(t, f)
}

func TestPublishGenesisDirUnresolvedReadAndAckRemainUnknown(t *testing.T) {
	for _, name := range []string{"read-unavailable", "ack-unavailable"} {
		t.Run(name, func(t *testing.T) {
			f := newGenesisDirFixture(t, nil)
			err := publishGenesisDirWith(context.Background(), f.dir, f.journal, f.pin, func(actual error) {
				if actual != nil {
					t.Fatal("GENESIS_UNKNOWN_FIXTURE_CREATE_FAILED")
				}
				if name == "read-unavailable" {
					_ = f.dir.Close()
					return
				}
				_ = f.journal.Close()
			})
			if !errors.Is(err, ErrGenesisUnknown) || errors.Is(err, ErrGenesisReview) {
				t.Fatal("GENESIS_UNRESOLVED_OUTCOME_MISCLASSIFIED")
			}
			reopened, err := vaultfilebackend.OpenExistingDir(f.backendRoot)
			if err != nil {
				t.Fatal("GENESIS_UNRESOLVED_REMOTE_REOPEN_FAILED")
			}
			defer reopened.Close()
			remote, err := reopened.Read(context.Background(), f.intent.Name)
			if err != nil || !bytes.Equal(remote.Bytes, f.intent.SealedBytes) {
				t.Fatal("GENESIS_UNRESOLVED_REMOTE_NOT_PRESERVED")
			}
			assertGenesisIntentPending(t, f)
		})
	}
}

func TestPublishGenesisDirInvalidIntentOrPinDoesNoBackendCreate(t *testing.T) {
	for _, name := range []string{"wrong-operation", "wrong-policy-digest", "foreign-pin"} {
		t.Run(name, func(t *testing.T) {
			mutate := func(i *vaultfilejournal.GenesisIntent) {
				switch name {
				case "wrong-operation":
					i.OperationID = "other-operation"
				case "wrong-policy-digest":
					i.PolicyDigest[0] ^= 1
				}
			}
			f := newGenesisDirFixture(t, mutate)
			if name == "foreign-pin" {
				f.pin.OwnerRootPublicKey[0] ^= 1
			}
			if err := PublishGenesisDir(context.Background(), f.dir, f.journal, f.pin); !errors.Is(err, ErrVerification) {
				t.Fatal("GENESIS_INVALID_INPUT_WAS_NOT_REFUSED")
			}
			if _, err := f.dir.Read(context.Background(), f.intent.Name); !errors.Is(err, vaultfilebackend.ErrNotFound) {
				t.Fatal("GENESIS_INVALID_INPUT_CREATED_BACKEND_VALUE")
			}
			assertGenesisIntentPending(t, f)
		})
	}
}

func TestPublishGenesisDirRequiresReopenedDurableIntentBeforeBackendCreate(t *testing.T) {
	for _, name := range []string{"nil-intent", "closed-intent"} {
		t.Run(name, func(t *testing.T) {
			f := newGenesisDirFixture(t, nil)
			j := f.journal
			if name == "nil-intent" {
				j = nil
			} else if err := j.Close(); err != nil {
				t.Fatal("GENESIS_CLOSED_INTENT_FIXTURE_FAILED")
			}
			if err := PublishGenesisDir(context.Background(), f.dir, j, f.pin); err == nil {
				t.Fatal("GENESIS_WITHOUT_ACTIVE_INTENT_ACCEPTED")
			}
			if _, err := f.dir.Read(context.Background(), f.intent.Name); !errors.Is(err, vaultfilebackend.ErrNotFound) {
				t.Fatal("GENESIS_WITHOUT_ACTIVE_INTENT_CREATED_REMOTE")
			}
			assertGenesisIntentPending(t, f)
		})
	}
}

// A lost response can leave G remotely committed and the local intent
// pending. If that remote object later disappears, reopening the intent must
// not authorize a second Create of the same old G.
func TestPublishGenesisDirReopenNeverRecreatesOldGAfterRemoteDeletion(t *testing.T) {
	f := newGenesisDirFixture(t, nil)
	ctx := context.Background()
	err := publishGenesisDirWith(ctx, f.dir, f.journal, f.pin, func(actual error) {
		if actual != nil {
			t.Fatal("GENESIS_FIRST_CREATE_DID_NOT_COMMIT")
		}
		if err := f.dir.Close(); err != nil {
			t.Fatal("GENESIS_FIRST_DIR_CLOSE_FAILED")
		}
	})
	if !errors.Is(err, ErrGenesisUnknown) {
		t.Fatal("GENESIS_FIRST_LOST_RESPONSE_NOT_UNKNOWN")
	}
	if err := f.journal.Close(); err != nil {
		t.Fatal("GENESIS_FIRST_JOURNAL_CLOSE_FAILED")
	}
	// Delete only the committed record in this owned temporary Dir store;
	// leave its namespace, lock and other state in place.
	sum := sha256.Sum256([]byte(f.intent.Name))
	record := filepath.Join(f.backendRoot, "vaultfile-backend", "v1", "data", hex.EncodeToString(sum[:]))
	if err := os.Remove(record); err != nil {
		t.Fatal("GENESIS_OWNED_REMOTE_DELETE_FAILED")
	}
	dir, err := vaultfilebackend.OpenExistingDir(f.backendRoot)
	if err != nil {
		t.Fatal("GENESIS_EMPTY_REMOTE_REOPEN_FAILED")
	}
	defer dir.Close()
	j, err := vaultfilejournal.OpenExistingIntent(f.journalPath)
	if err != nil {
		t.Fatal("GENESIS_PENDING_JOURNAL_REOPEN_FAILED")
	}
	defer j.Close()
	if err := PublishGenesisDir(ctx, dir, j, f.pin); !errors.Is(err, ErrGenesisUnknown) {
		t.Fatal("GENESIS_REOPEN_RECREATED_OLD_G")
	}
	if _, err := dir.Read(ctx, f.intent.Name); !errors.Is(err, vaultfilebackend.ErrNotFound) {
		t.Fatal("GENESIS_REOPEN_CREATED_REMOTE_VALUE")
	}
	f.journal = j
	assertGenesisIntentPending(t, f)
}

func TestPublishGenesisDirClaimCommittedBeforeCreateOnlyReads(t *testing.T) {
	f := newGenesisDirFixture(t, nil)
	result, err := f.journal.ClaimGenesisAttempt(f.intent)
	if err != nil || result != vaultfilejournal.GenesisAttemptNewlyClaimed || f.journal.Close() != nil {
		t.Fatal("GENESIS_PRECREATE_CLAIM_FIXTURE_FAILED")
	}
	j, err := vaultfilejournal.OpenExistingIntent(f.journalPath)
	if err != nil {
		t.Fatal("GENESIS_PRECREATE_CLAIM_REOPEN_FAILED")
	}
	defer j.Close()
	if err := PublishGenesisDir(context.Background(), f.dir, j, f.pin); !errors.Is(err, ErrGenesisUnknown) {
		t.Fatal("GENESIS_PRECREATE_CLAIM_RECREATED_G")
	}
	if _, err := f.dir.Read(context.Background(), f.intent.Name); !errors.Is(err, vaultfilebackend.ErrNotFound) {
		t.Fatal("GENESIS_PRECREATE_CLAIM_CREATED_REMOTE")
	}
	f.journal = j
	assertGenesisIntentPending(t, f)
}
