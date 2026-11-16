//go:build darwin || linux

package personal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
	bolt "go.etcd.io/bbolt"
)

func publishedGenesisBaselineFixture(t *testing.T) (genesisProducerFixture, VaultFileGenesisPublic, []byte) {
	t.Helper()
	f := newGenesisProducerFixture(t)
	projection, err := f.session.PrepareVaultFileGenesis(f.request(), f.password, f.key, f.kit)
	if err != nil {
		t.Fatal("GENESIS_BASELINE_PRODUCER_FAILED")
	}
	intent := loadProducedGenesis(t, f.journal)
	defer clear(intent.SealedBytes)
	hash := sha256.Sum256(intent.SealedBytes)
	rootPublic, err := hex.DecodeString(f.owner.OwnerRootPublicKey)
	if err != nil {
		t.Fatal("GENESIS_BASELINE_ROOT_PUBLIC_INVALID")
	}
	pin := &vaultfile.GenesisRootPin{VaultID: f.owner.VaultID,
		OwnerRootKeyID: f.owner.OwnerRootKeyID, OwnerRootPublicKey: ed25519.PublicKey(rootPublic)}
	backend, err := vaultfilebackend.OpenDir(filepath.Join(filepath.Dir(f.personal), "backend"))
	if err != nil {
		t.Fatal("GENESIS_BASELINE_BACKEND_OPEN_FAILED")
	}
	j, err := vaultfilejournal.OpenExistingIntent(f.journal)
	if err != nil {
		t.Fatal("GENESIS_BASELINE_INTENT_REOPEN_FAILED")
	}
	if err := vaultfilepublish.PublishGenesisDir(context.Background(), backend, j, pin); err != nil ||
		j.Close() != nil || backend.Close() != nil {
		t.Fatal("GENESIS_BASELINE_REAL_PUBLISH_ACK_FAILED")
	}
	return f, projection, bytes.Clone(hash[:])
}

func TestVerifyAckedVaultFileGenesisRealPublishAndRefusals(t *testing.T) {
	f, projection, hash := publishedGenesisBaselineFixture(t)
	before, err := os.ReadFile(f.journal)
	if err != nil {
		t.Fatal("GENESIS_BASELINE_JOURNAL_READ_FAILED")
	}
	verified, err := f.session.VerifyAckedVaultFileGenesis(f.request(), hash, f.password, f.key, f.kit)
	if err != nil || !reflect.DeepEqual(verified, projection) {
		t.Fatal("GENESIS_BASELINE_FRESH_VERIFY_FAILED")
	}
	after, err := os.ReadFile(f.journal)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("GENESIS_BASELINE_VERIFICATION_CHANGED_JOURNAL")
	}
	wrongHash := bytes.Clone(hash)
	wrongHash[0] ^= 1
	if _, err := f.session.VerifyAckedVaultFileGenesis(f.request(), wrongHash, f.password, f.key, f.kit); !errors.Is(err, ErrVaultFileGenesisIntent) {
		t.Fatal("GENESIS_BASELINE_WRONG_G_HASH_ACCEPTED")
	}
	if _, err := f.session.VerifyAckedVaultFileGenesis(f.request(), hash, f.password, f.key, f.oldKit); !errors.Is(err, ErrVaultFileGenesisRecovery) {
		t.Fatal("GENESIS_BASELINE_OLD_KIT_ACCEPTED")
	}
	old := f.request()
	old.ArchivePath = f.oldArchive
	if _, err := f.session.VerifyAckedVaultFileGenesis(old, hash, f.password, f.key, f.oldKit); !errors.Is(err, ErrVaultFileGenesisRecovery) {
		t.Fatal("GENESIS_BASELINE_OLD_ARCHIVE_ACCEPTED")
	}
	f.session.mu.Lock()
	f.session.fullUnlock = time.Time{}
	f.session.mu.Unlock()
	if _, err := f.session.VerifyAckedVaultFileGenesis(f.request(), hash, f.password, f.key, f.kit); !errors.Is(err, ErrVaultFileFullFactorRequired) {
		t.Fatal("GENESIS_BASELINE_QUICK_UNLOCK_ACCEPTED")
	}
	f.session.mu.Lock()
	f.session.fullUnlock = time.Now().Add(-passkeyTransferFullFactorWindow)
	f.session.mu.Unlock()
	if _, err := f.session.VerifyAckedVaultFileGenesis(f.request(), hash, f.password, f.key, f.kit); !errors.Is(err, ErrVaultFileFullFactorRequired) {
		t.Fatal("GENESIS_BASELINE_EXPIRED_UNLOCK_ACCEPTED")
	}
	f.session.Lock()
	if _, err := f.session.VerifyAckedVaultFileGenesis(f.request(), hash, f.password, f.key, f.kit); !errors.Is(err, ErrSessionLocked) {
		t.Fatal("GENESIS_BASELINE_LOCKED_SESSION_ACCEPTED")
	}
	restored := filepath.Join(filepath.Dir(f.personal), "restored.ll")
	newKey := bytes.Repeat([]byte{0x59}, 16)
	if Restore(f.archive, restored, string(f.password), f.key, string(f.kit), newKey) != nil {
		t.Fatal("GENESIS_BASELINE_RESTORE_FAILED")
	}
	restoredSession, err := UnlockSession(restored, f.password, newKey, time.Minute)
	if err != nil {
		t.Fatal("GENESIS_BASELINE_RESTORED_UNLOCK_FAILED")
	}
	defer restoredSession.Lock()
	if _, err := restoredSession.VerifyAckedVaultFileGenesis(f.request(), hash, f.password, f.key, f.kit); !errors.Is(err, ErrVaultFileGenesisIntent) {
		t.Fatal("GENESIS_BASELINE_FOREIGN_ORDINARY_IDENTITY_ACCEPTED")
	}
}

func TestVerifyAckedVaultFileGenesisRejectsNonSoleState(t *testing.T) {
	f, _, hash := publishedGenesisBaselineFixture(t)
	original, err := os.ReadFile(f.journal)
	if err != nil {
		t.Fatal("GENESIS_BASELINE_JOURNAL_COPY_FAILED")
	}
	for _, tc := range []struct {
		name   string
		change func(string) error
	}{
		{name: "generation-one", change: func(path string) error {
			j, err := vaultfilejournal.OpenExisting(path)
			if err != nil {
				return err
			}
			state, err := j.LoadState()
			if err == nil {
				err = j.UpdateWorking(0, state.BaseBytes)
			}
			closeErr := j.Close()
			if err != nil {
				return err
			}
			return closeErr
		}},
		{name: "prepared", change: func(path string) error { return injectGenesisBaselineForeignKey(path, "prepared") }},
		{name: "legacy", change: func(path string) error { return injectGenesisBaselineForeignKey(path, "proposal") }},
		{name: "unknown", change: func(path string) error { return injectGenesisBaselineForeignKey(path, "foreign") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(filepath.Dir(f.journal), tc.name+".journal")
			if err := os.WriteFile(path, original, 0600); err != nil || tc.change(path) != nil {
				t.Fatal("GENESIS_BASELINE_FOREIGN_FIXTURE_FAILED")
			}
			req := f.request()
			req.IntentPath = path
			if _, err := f.session.VerifyAckedVaultFileGenesis(req, hash, f.password, f.key, f.kit); !errors.Is(err, ErrVaultFileGenesisIntent) {
				t.Fatal("GENESIS_BASELINE_NONSOLE_STATE_ACCEPTED")
			}
		})
	}
}

func injectGenesisBaselineForeignKey(path, key string) error {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("journal")).Put([]byte(key), []byte("unknown"))
	})
	closeErr := db.Close()
	if err != nil {
		return err
	}
	return closeErr
}
