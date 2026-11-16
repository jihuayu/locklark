//go:build darwin || linux

package vaultfilejournal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

func TestGenesisAttemptClaimReopenAndAck(t *testing.T) {
	path := filepath.Join(privateDir(t), "journal.db")
	intent := genesisIntentFixture()
	if err := CreateNewGenesisIntent(path, intent); err != nil {
		t.Fatal("ATTEMPT_INTENT_CREATE_FAILED")
	}
	j, err := OpenExistingIntent(path)
	if err != nil {
		t.Fatal("ATTEMPT_INTENT_OPEN_FAILED")
	}
	result, err := j.ClaimGenesisAttempt(intent)
	if err != nil || result != GenesisAttemptNewlyClaimed || j.Close() != nil {
		t.Fatal("ATTEMPT_FIRST_CLAIM_FAILED")
	}
	j, err = OpenExistingIntent(path)
	if err != nil {
		t.Fatal("ATTEMPT_REOPEN_FAILED")
	}
	result, err = j.ClaimGenesisAttempt(intent)
	if err != nil || result != GenesisAttemptPreviouslyClaimed {
		t.Fatal("ATTEMPT_REOPEN_GRANTED_SECOND_CREATE")
	}
	loaded, err := j.Load()
	if err != nil || !sameGenesisIntent(loaded, intent) {
		t.Fatal("ATTEMPT_MARKER_CHANGED_INTENT")
	}
	if err := j.AckGenesis(intent, bytes.Clone(intent.SealedBytes), vaultfilebackend.Revision("owned-revision")); err != nil || j.Close() != nil {
		t.Fatal("ATTEMPT_ACK_FAILED")
	}
	state, err := OpenExisting(path)
	if err != nil {
		t.Fatal("ATTEMPT_ACK_STATE_REOPEN_FAILED")
	}
	defer state.Close()
	if err := state.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b.Get([]byte(genesisIntentKey)) != nil || b.Get([]byte(genesisAttemptKey)) != nil {
			return ErrCorrupt
		}
		return nil
	}); err != nil {
		t.Fatal("ATTEMPT_ACK_LEFT_MARKER")
	}
}

func TestGenesisAttemptClaimCommitResultUnknownDoesNotGrantCreate(t *testing.T) {
	for _, commit := range []bool{false, true} {
		name := "rollback"
		if commit {
			name = "commit-then-error"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(privateDir(t), "journal.db")
			intent := genesisIntentFixture()
			if err := CreateNewGenesisIntent(path, intent); err != nil {
				t.Fatal("ATTEMPT_UNKNOWN_FIXTURE_FAILED")
			}
			j, err := OpenExistingIntent(path)
			if err != nil {
				t.Fatal("ATTEMPT_UNKNOWN_OPEN_FAILED")
			}
			fault := errors.New("owned attempt commit result fault")
			reached := false
			result, err := j.claimGenesisAttemptWithUpdate(intent, func(fn func(*bolt.Tx) error) error {
				reached = true
				if commit {
					if err := j.journal.db.Update(fn); err != nil {
						return err
					}
					return fault
				}
				return j.journal.db.Update(func(tx *bolt.Tx) error {
					if err := fn(tx); err != nil {
						return err
					}
					return fault
				})
			})
			if !reached || result != 0 || !errors.Is(err, fault) || j.Close() != nil {
				t.Fatal("ATTEMPT_UNKNOWN_GRANTED_CREATE")
			}
			j, err = OpenExistingIntent(path)
			if err != nil {
				t.Fatal("ATTEMPT_UNKNOWN_REOPEN_FAILED")
			}
			defer j.Close()
			result, err = j.ClaimGenesisAttempt(intent)
			want := GenesisAttemptNewlyClaimed
			if commit {
				want = GenesisAttemptPreviouslyClaimed
			}
			if err != nil || result != want {
				t.Fatal("ATTEMPT_UNKNOWN_REOPEN_SHAPE_WRONG")
			}
		})
	}
}

func TestGenesisAttemptMarkerMustBindExactIntent(t *testing.T) {
	for _, name := range []string{"malformed-marker", "changed-intent", "isolated-marker"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(privateDir(t), "journal.db")
			intent := genesisIntentFixture()
			if name == "isolated-marker" {
				j, err := Open(path)
				if err != nil || j.Close() != nil {
					t.Fatal("ATTEMPT_ISOLATED_FIXTURE_FAILED")
				}
			} else {
				if err := CreateNewGenesisIntent(path, intent); err != nil {
					t.Fatal("ATTEMPT_BINDING_FIXTURE_FAILED")
				}
				j, err := OpenExistingIntent(path)
				if err != nil {
					t.Fatal("ATTEMPT_BINDING_OPEN_FAILED")
				}
				if result, err := j.ClaimGenesisAttempt(intent); err != nil || result != GenesisAttemptNewlyClaimed || j.Close() != nil {
					t.Fatal("ATTEMPT_BINDING_CLAIM_FAILED")
				}
			}
			db, err := bolt.Open(path, 0600, nil)
			if err != nil {
				t.Fatal("ATTEMPT_TAMPER_OPEN_FAILED")
			}
			err = db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(bucketName))
				switch name {
				case "malformed-marker":
					return b.Put([]byte(genesisAttemptKey), []byte("bad"))
				case "changed-intent":
					other := cloneGenesisIntent(intent)
					other.OperationID = "other-operation"
					return b.Put([]byte(genesisIntentKey), encodeGenesisIntent(other))
				default:
					return b.Put([]byte(genesisAttemptKey), encodeGenesisAttempt(encodeGenesisIntent(intent)))
				}
			})
			if err != nil || db.Close() != nil {
				t.Fatal("ATTEMPT_TAMPER_FIXTURE_FAILED")
			}
			before, err := os.ReadFile(path)
			info, statErr := os.Lstat(path)
			if err != nil || statErr != nil {
				t.Fatal("ATTEMPT_TAMPER_SNAPSHOT_FAILED")
			}
			if j, err := OpenExistingIntent(path); j != nil || !errors.Is(err, ErrCorrupt) {
				if j != nil {
					_ = j.Close()
				}
				t.Fatal("ATTEMPT_MALFORMED_MARKER_ACCEPTED")
			}
			if j, err := Open(path); j != nil || !errors.Is(err, ErrPendingGenesisIntent) {
				if j != nil {
					_ = j.Close()
				}
				t.Fatal("ATTEMPT_LEGACY_OPEN_ACCEPTED")
			}
			after, err := os.ReadFile(path)
			current, statErr := os.Lstat(path)
			if err != nil || statErr != nil || !os.SameFile(info, current) || !bytes.Equal(before, after) {
				t.Fatal("ATTEMPT_REFUSAL_MUTATED_JOURNAL")
			}
		})
	}
}

func TestGenesisAttemptWrongExpectedDoesNotMutateIntent(t *testing.T) {
	path := filepath.Join(privateDir(t), "journal.db")
	intent := genesisIntentFixture()
	if err := CreateNewGenesisIntent(path, intent); err != nil {
		t.Fatal("ATTEMPT_EXPECTED_FIXTURE_FAILED")
	}
	j, err := OpenExistingIntent(path)
	if err != nil {
		t.Fatal("ATTEMPT_EXPECTED_OPEN_FAILED")
	}
	defer j.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("ATTEMPT_EXPECTED_SNAPSHOT_FAILED")
	}
	wrong := cloneGenesisIntent(intent)
	wrong.OperationID = "wrong-operation"
	if result, err := j.ClaimGenesisAttempt(wrong); result != 0 || !errors.Is(err, ErrGenesisMismatch) {
		t.Fatal("ATTEMPT_WRONG_EXPECTED_ACCEPTED")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("ATTEMPT_WRONG_EXPECTED_MUTATED_JOURNAL")
	}
}
