package personal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func TestReferenceEventValidation(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	base := Event{Sequence: 2, UTC: time.Now().UTC().Format(time.RFC3339Nano), Session: strings.Repeat("a", 32), Actor: "local-owner", Action: referenceRejectAction, Result: "stale", Previous: strings.Repeat("b", 64)}
	verify := func(e Event) error {
		e.Signature = ed25519.Sign(private, e.proof())
		return e.verify(private.Public().(ed25519.PublicKey), 2, base.Previous)
	}
	for _, result := range []string{"stale", "not-found", "ambiguous", "wrong-type"} {
		e := base
		e.Result = result
		if err := verify(e); err != nil {
			t.Fatal("valid rejection refused", err)
		}
	}
	for _, mutate := range []func(*Event){
		func(e *Event) { e.Item = strings.Repeat("c", 32) },
		func(e *Event) { e.BaseRevision = strings.Repeat("d", 64) },
		func(e *Event) { e.Link = strings.Repeat("e", 32) },
		func(e *Event) { e.Generation = &password.Profile{} },
		func(e *Event) { e.Result = "succeeded" },
		func(e *Event) { e.Result = "intent" },
		func(e *Event) { e.Result = "op://Personal/private/password" },
		func(e *Event) { e.Action = referenceDisclosureAction },
		func(e *Event) { e.Action = "reference.list" },
	} {
		e := base
		mutate(&e)
		if verify(e) == nil {
			t.Fatal("invalid signed reference event accepted")
		}
	}
	base.Action, base.Result = "reference.list", "succeeded"
	if err := verify(base); err != nil {
		t.Fatal("valid reference listing refused", err)
	}
}

func TestReferenceIndexAndAtomicDisclosure(t *testing.T) {
	path, key, target := otpFixture(t)
	index, err := References(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	if !idOK(index.VaultID) || index.VaultName != "Personal" || len(index.Items) != 2 || index.Items[0].ID != target.ID || index.Items[0].Revision != target.Revision {
		t.Fatal("invalid reference index")
	}
	raw := index.Items[0].References["password"]
	if raw != "op://"+index.VaultID+"/"+target.ID+"/password" {
		t.Fatal("reference is not canonical IDs")
	}
	var output bytes.Buffer
	var intent Event
	r, err := RevealReference(path, "fixture", key, raw, target.Revision, disclosureWriter(func(p []byte) (int, error) {
		events, err := Audit(path, "fixture", key)
		if err != nil {
			t.Fatal(err)
		}
		intent = events[len(events)-2]
		if intent.Action != "item.reveal.password" || intent.Item != target.ID || intent.BaseRevision != target.Revision || intent.Result != "intent" {
			t.Fatal("reference not bound to durable stable target")
		}
		return output.Write(p)
	}))
	if err != nil || r.Intent != intent.hash() {
		t.Fatal("reference disclosure failed", err)
	}
	var value string
	if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &value) != nil || value != "private-value\t\"quoted\"\n" {
		t.Fatal("wrong referenced value")
	}
	output.Reset()
	if _, err = RevealReference(path, "fixture", key, "OP://personal/"+strings.ToUpper(target.ID)+"/USERNAME", target.Revision, &output); err != nil || output.String() != "\"fixture-user\"\r\n" {
		t.Fatal("alias/case resolution failed", err)
	}
	option, err := referenceOption(index.Items[0].References["otp"], target.Revision, true)
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	_, err = revealOTP(&output, func() time.Time { return time.Unix(59, 0) }, func() (result, error) {
		return command(path, "fixture", key, referenceDisclosureAction, vault.Item{}, nil, option)
	})
	if err != nil || output.String() != "\"94287082\"\r\n" {
		t.Fatal("OTP reference failed", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal([]any{index, events, r})
	for _, secret := range []string{"fixture-user", "private-value", otpFixtureSeed, "94287082"} {
		if bytes.Contains(public, []byte(secret)) {
			t.Fatal("reference metadata/audit leaked value")
		}
	}
}

func TestReferenceAuthenticationRollbackAndCatalogFailure(t *testing.T) {
	path, key, target := revealFixture(t)
	index, err := References(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	raw := index.Items[0].References["password"]
	var output bytes.Buffer
	if _, err := RevealReference(path, "wrong", key, raw, target.Revision, &output); err == nil || output.Len() != 0 {
		t.Fatal("wrong factor disclosed")
	}
	if got, err := References(path, "wrong", key); err == nil || got.Items != nil || got.VaultID != "" {
		t.Fatal("wrong factor returned metadata")
	}
	option, err := referenceOption(raw, target.Revision, false)
	if err != nil {
		t.Fatal(err)
	}
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected reference commit failure")
	_, err = disclosePrepared(&output, func() (result, error) {
		return commandWithUpdate(func(fn func(*bolt.Tx) error) error {
			return db.Update(func(tx *bolt.Tx) error {
				if err := fn(tx); err != nil {
					return err
				}
				return injected
			})
		}, "fixture", key, referenceDisclosureAction, vault.Item{}, nil, option)
	})
	db.Close()
	if !errors.Is(err, injected) || output.Len() != 0 {
		t.Fatal("rolled-back reference disclosed", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if revealAction(e.Action) || e.Action == referenceRejectAction {
			t.Fatal("failed authentication/commit left event")
		}
	}
	// A title accepted by native storage can exceed the reference catalog's
	// bounds. Reject the whole index and retain the direct stable-ID path.
	second := index.Items[1]
	if _, err := EditLogin(path, "fixture", key, Edit{ID: second.ID, Revision: second.Revision, Field: "title", Value: strings.Repeat("x", 1025)}); err != nil {
		t.Fatal(err)
	}
	if got, err := References(path, "fixture", key); err == nil || got.Items != nil || got.VaultID != "" {
		t.Fatal("invalid catalog returned partial index")
	}
	if _, err := RevealReference(path, "fixture", key, raw, target.Revision, &output); err == nil || output.Len() != 0 {
		t.Fatal("invalid catalog disclosed")
	}
	if _, err := RevealLogin(path, "fixture", key, target, &output); err != nil {
		t.Fatal("direct ID fallback failed", err)
	}
}

func TestReferenceConcurrentEditAndRecovery(t *testing.T) {
	path, key, target := revealFixture(t)
	index, err := References(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	raw := index.Items[0].References["password"]
	var output bytes.Buffer
	var readErr, editErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, readErr = RevealReference(path, "fixture", key, raw, target.Revision, &output)
	}()
	go func() {
		defer wg.Done()
		_, editErr = EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "password", Value: "reference-replacement"})
	}()
	wg.Wait()
	if editErr != nil {
		t.Fatal(editErr)
	}
	if readErr == nil {
		var value string
		if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &value) != nil || value != "private-value\t\"quoted\"\n" {
			t.Fatal("reference disclosed different revision")
		}
	} else if !errors.Is(readErr, ErrConflict) || output.Len() != 0 {
		t.Fatal("unexpected reference race outcome", readErr)
	}
	output.Reset()
	if _, err := RevealReference(path, "fixture", key, raw, target.Revision, &output); !errors.Is(err, ErrConflict) || output.Len() != 0 {
		t.Fatal("stale reference disclosed", err)
	}
	archive := filepath.Join(t.TempDir(), "backup.llb")
	backup, err := PrepareBackup(path, archive, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	kit := backup.Material()
	if err := backup.Publish(); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.ll")
	recovery, err := PrepareRestore(archive, restored, "fixture", key, kit)
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	fresh := bytes.Repeat([]byte{6}, 16)
	if err := recovery.Publish(fresh); err != nil {
		t.Fatal(err)
	}
	current, err := References(restored, "fixture", fresh)
	if err != nil {
		t.Fatal(err)
	}
	if current.VaultID == index.VaultID || current.Items[0].ID != target.ID || current.Items[0].Revision == target.Revision {
		t.Fatal("restore did not renew reference identity/revision")
	}
	if _, err := RevealReference(restored, "fixture", fresh, raw, current.Items[0].Revision, &output); !errors.Is(err, reference.ErrNotFound) || output.Len() != 0 {
		t.Fatal("restored vault accepted old canonical reference", err)
	}
	newRef := current.Items[0].References["password"]
	if _, err := RevealReference(restored, "fixture", fresh, newRef, target.Revision, &output); !errors.Is(err, ErrConflict) || output.Len() != 0 {
		t.Fatal("restored vault accepted old revision", err)
	}
	if _, err := RevealReference(restored, "fixture", fresh, newRef, current.Items[0].Revision, &output); err != nil || output.String() != "\"reference-replacement\"\r\n" {
		t.Fatal("restored reference failed", err)
	}
	chains, err := ArchivedAudit(restored, "fixture", fresh)
	if err != nil {
		t.Fatal(err)
	}
	stale := 0
	for _, chain := range chains {
		for _, event := range chain.Events {
			if event.Action == referenceRejectAction && event.Result == "stale" {
				stale++
			}
		}
	}
	if stale == 0 {
		t.Fatal("restore lost reference rejection history")
	}
}

func TestReferenceRefusalsAndIdentityAmbiguity(t *testing.T) {
	path, key, target := otpFixture(t)
	index, err := References(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	for _, test := range []struct {
		raw, revision string
		otp           bool
		want          error
	}{
		{"op://Personal/same/password", target.Revision, false, reference.ErrAmbiguous},
		{"op://Personal/missing-private-selector/password", target.Revision, false, reference.ErrNotFound},
		{index.Items[0].References["otp"], target.Revision, false, ErrReferenceType},
		{index.Items[0].References["password"], target.Revision, true, ErrReferenceType},
		{index.Items[0].References["password"], strings.Repeat("0", 64), false, ErrConflict},
		{"op://wrong-vault/" + target.ID + "/password", target.Revision, false, reference.ErrNotFound},
	} {
		var err error
		if test.otp {
			_, err = RevealOTPReference(path, "fixture", key, test.raw, test.revision, &output)
		} else {
			_, err = RevealReference(path, "fixture", key, test.raw, test.revision, &output)
		}
		if !errors.Is(err, test.want) || output.Len() != 0 {
			t.Fatal("reference refusal failed", err)
		}
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	var outcomes []string
	for _, e := range events {
		if e.Action == referenceRejectAction {
			outcomes = append(outcomes, e.Result)
			if e.Item != "" || e.BaseRevision != "" || e.Link != "" || e.Generation != nil {
				t.Fatal("rejection recorded caller/target data")
			}
		}
	}
	if strings.Join(outcomes, ",") != "ambiguous,not-found,wrong-type,wrong-type,stale,not-found" {
		t.Fatal("wrong reference rejection categories", outcomes)
	}
	rawEvents, _ := json.Marshal(events)
	if bytes.Contains(rawEvents, []byte("missing-private-selector")) || bytes.Contains(rawEvents, []byte("op://")) {
		t.Fatal("reference persisted in audit")
	}
	// A title equal to another item's ID cannot silently override/prefer that ID.
	second := index.Items[1]
	if _, err = EditLogin(path, "fixture", key, Edit{ID: second.ID, Revision: second.Revision, Field: "title", Value: target.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = RevealReference(path, "fixture", key, index.Items[0].References["password"], target.Revision, &output); !errors.Is(err, reference.ErrAmbiguous) || output.Len() != 0 {
		t.Fatal("name impersonating ID was not ambiguous", err)
	}
	if _, err = RevealLogin(path, "fixture", key, RevealTarget{target.ID, target.Revision, "password"}, &output); err != nil {
		t.Fatal("direct stable-ID path regressed", err)
	}
}
