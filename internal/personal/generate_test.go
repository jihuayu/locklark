package personal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func TestGenerateSavedLoginAndAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.ll")
	key := bytes.Repeat([]byte{6}, 16)
	if err := Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	receipt, err := GenerateLogin(path, "fixture", key, "Generated login", "private-user", 24)
	if err != nil {
		t.Fatal(err)
	}
	items := readStoredItems(t, path, "fixture", key)
	if len(items) != 1 || items[0].ID != receipt.ID || len(items[0].Password) != 24 || receipt.Profile.Length != 24 || receipt.Profile.EntropyBits < 128 {
		t.Fatal("generated login not saved")
	}
	for _, r := range items[0].Password {
		if !strings.ContainsRune(password.DefaultAlphabet, r) {
			t.Fatal("unexpected password alphabet")
		}
	}
	rows, err := List(path, "fixture", key)
	if err != nil || rows[0].Revision != receipt.Revision {
		t.Fatal("receipt revision mismatch", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	if events[1].Action != "item.generate" || events[1].Generation == nil || *events[1].Generation != receipt.Profile || events[1].hash() != receipt.Revision {
		t.Fatal("missing generation provenance")
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal([]any{receipt, events})
	for _, secret := range []string{items[0].Password, "private-user"} {
		if bytes.Contains(disk, []byte(secret)) || bytes.Contains(public, []byte(secret)) {
			t.Fatal("secret leaked outside encrypted value")
		}
	}
	var shown bytes.Buffer
	if _, err = RevealLogin(path, "fixture", key, RevealTarget{receipt.ID, receipt.Revision, "password"}, &shown); err != nil {
		t.Fatal(err)
	}
	var value string
	if json.Unmarshal(bytes.TrimSpace(shown.Bytes()), &value) != nil || value != items[0].Password {
		t.Fatal("generated password cannot be explicitly revealed")
	}
}

func TestGenerationAuthorizationAndRollback(t *testing.T) {
	path, key, target := revealFixture(t)
	option, err := generationOption(24)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	option.generation.generate = func(password.Policy) (password.Secret, error) {
		calls++
		return password.Secret{}, errors.New("private-random-provider-detail")
	}
	for _, test := range []struct {
		pw, id, revision string
		key              []byte
		want             error
	}{
		{"wrong", target.ID, target.Revision, key, invalid},
		{"fixture", target.ID, target.Revision, bytes.Repeat([]byte{1}, 16), invalid},
		{"fixture", strings.Repeat("a", 32), target.Revision, key, ErrNotFound},
		{"fixture", target.ID, strings.Repeat("0", 64), key, ErrConflict},
	} {
		_, err = command(path, test.pw, test.key, "item.regenerate.password", vault.Item{}, &Edit{ID: test.id, Revision: test.revision, Field: "password"}, option)
		if !errors.Is(err, test.want) || calls != 0 {
			t.Fatal("generated before authorization", err, calls)
		}
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = command(path, "fixture", key, "item.regenerate.password", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: "password"}, option)
	after, readErr := os.ReadFile(path)
	if !errors.Is(err, password.ErrRandom) || calls != 1 || readErr != nil || !bytes.Equal(before, after) {
		t.Fatal("random failure did not preserve complete database", err)
	}
	_, err = command(path, "fixture", key, "item.generate", vault.Item{Kind: "login", Title: "Generated"}, nil, option)
	after, readErr = os.ReadFile(path)
	if !errors.Is(err, password.ErrRandom) || calls != 2 || readErr != nil || !bytes.Equal(before, after) {
		t.Fatal("failed generated creation changed the database", err)
	}
	option.generation.generate = password.Generate
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected transaction failure")
	r, err := commandWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return injected
		})
	}, "fixture", key, "item.regenerate.password", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: "password"}, option)
	db.Close()
	if !errors.Is(err, injected) || r.id != "" || r.revision != "" || r.profile != (password.Profile{}) {
		t.Fatal("failed transaction produced a success result")
	}
	items := readStoredItems(t, path, "fixture", key)
	if items[0].Password != "private-value\t\"quoted\"\n" {
		t.Fatal("rollback replaced original value")
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if generatedAction(event.Action) && event.Result == "succeeded" {
			t.Fatal("failed generation left success event")
		}
	}
	// Corrupt authenticated history must also refuse before touching randomness.
	db, err = existing(path)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put(tipKey, []byte("damaged")) })
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	option.generation.generate = func(password.Policy) (password.Secret, error) { calls++; return password.Secret{}, password.ErrRandom }
	if _, err = command(path, "fixture", key, "item.generate", vault.Item{Kind: "login", Title: "Test"}, nil, option); err == nil || calls != 0 {
		t.Fatal("damaged history allowed generation")
	}
}

func TestGenerationEventProfileValidation(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	profile, _ := password.Validate(password.DefaultPolicy())
	base := Event{Generation: &profile, Sequence: 2, UTC: time.Now().UTC().Format(time.RFC3339Nano), Session: strings.Repeat("a", 32), Actor: "local-owner", Action: "item.generate", Item: strings.Repeat("b", 32), Result: "succeeded", Previous: strings.Repeat("c", 64)}
	verify := func(event Event) error {
		event.Signature = ed25519.Sign(private, event.proof())
		return event.verify(private.Public().(ed25519.PublicKey), 2, base.Previous)
	}
	if err := verify(base); err != nil {
		t.Fatal("valid generation rejected", err)
	}
	for _, mutate := range []func(*Event){
		func(e *Event) { e.Generation = nil },
		func(e *Event) { p := *e.Generation; p.EntropyBits++; e.Generation = &p },
		func(e *Event) { p := *e.Generation; p.Length = 21; e.Generation = &p },
		func(e *Event) { p := *e.Generation; p.AlphabetSize = 2; e.Generation = &p },
		func(e *Event) { e.Action = "item.add" },
		func(e *Event) {
			e.Action = "item.regenerate.password"
			e.BaseRevision = strings.Repeat("d", 64)
			e.Result = "conflict"
		},
	} {
		event := base
		mutate(&event)
		if verify(event) == nil {
			t.Fatal("invalid generation profile accepted")
		}
	}
	base.Action = "item.regenerate.password"
	base.BaseRevision = strings.Repeat("d", 64)
	if err := verify(base); err != nil {
		t.Fatal("valid regeneration rejected", err)
	}
	base.Generation = nil
	base.Result = "conflict"
	if err := verify(base); err != nil {
		t.Fatal("valid refusal rejected", err)
	}
}

func TestGenerationHistoryRecovery(t *testing.T) {
	path, key, target := revealFixture(t)
	r, err := RegeneratePassword(path, "fixture", key, target.ID, target.Revision, 22)
	if err != nil {
		t.Fatal(err)
	}
	added, err := GenerateLogin(path, "fixture", key, "Generated", "", 256)
	if err != nil {
		t.Fatal(err)
	}
	before := readStoredItems(t, path, "fixture", key)
	archive := filepath.Join(t.TempDir(), "backup.llb")
	backup, err := PrepareBackup(path, archive, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	kit := backup.Material()
	if err = backup.Publish(); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.ll")
	recovery, err := PrepareRestore(archive, restored, "fixture", key, kit)
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	fresh := bytes.Repeat([]byte{7}, 16)
	if err = recovery.Publish(fresh); err != nil {
		t.Fatal(err)
	}
	after := readStoredItems(t, restored, "fixture", fresh)
	if len(after) != len(before) {
		t.Fatal("recovery lost generated items")
	}
	for i := range before {
		if before[i].ID != after[i].ID || before[i].Password != after[i].Password {
			t.Fatal("recovery changed generated values")
		}
	}
	chains, err := ArchivedAudit(restored, "fixture", fresh)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, chain := range chains {
		for _, event := range chain.Events {
			if generatedAction(event.Action) {
				count++
				if event.Generation == nil || !validGenerationProfile(*event.Generation) {
					t.Fatal("generation policy lost")
				}
			}
		}
	}
	if count != 2 {
		t.Fatal("generation history lost or duplicated")
	}
	for _, old := range []GenerationReceipt{r, added} {
		if _, err = RegeneratePassword(restored, "fixture", fresh, old.ID, old.Revision, 24); !errors.Is(err, ErrConflict) {
			t.Fatal("restored vault accepted original revision", err)
		}
	}
}

func TestRegenerateConcurrentAndRejectedPolicies(t *testing.T) {
	path, key, target := revealFixture(t)
	var wg sync.WaitGroup
	type result struct {
		receipt GenerationReceipt
		err     error
	}
	results := make(chan result, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := RegeneratePassword(path, "fixture", key, target.ID, target.Revision, 32)
			results <- result{r, e}
		}()
	}
	wg.Wait()
	close(results)
	var winner GenerationReceipt
	successes, conflicts := 0, 0
	for r := range results {
		if r.err == nil {
			successes++
			winner = r.receipt
		} else if errors.Is(r.err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(r.err)
		}
	}
	if successes != 1 || conflicts != 1 || winner.ID != target.ID || winner.Revision == target.Revision {
		t.Fatal("concurrent generation did not serialize")
	}
	saved := readStoredItems(t, path, "fixture", key)
	if len(saved[0].Password) != 32 || saved[0].Username != "fixture-user" || saved[1].Password != "other-password" {
		t.Fatal("regeneration changed wrong fields")
	}
	for _, length := range []int{-1, 0, 1, 21, 257} {
		if r, e := GenerateLogin(path, "fixture", key, "bad", "", length); e == nil || r != (GenerationReceipt{}) {
			t.Fatal("invalid generation policy accepted")
		}
		if r, e := RegeneratePassword(path, "fixture", key, target.ID, winner.Revision, length); e == nil || r != (GenerationReceipt{}) {
			t.Fatal("invalid regeneration policy accepted")
		}
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	var outcomes []string
	for _, e := range events {
		if e.Action == "item.regenerate.password" {
			outcomes = append(outcomes, e.Result)
			if (e.Generation != nil) != (e.Result == "succeeded") {
				t.Fatal("generation provenance attached to refusal")
			}
		}
	}
	if strings.Join(outcomes, ",") != "succeeded,conflict" {
		t.Fatal("incorrect audit", outcomes)
	}
}
