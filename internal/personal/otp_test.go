package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/totp"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

const otpFixtureSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
const otpFixtureURI = "otpauth://totp/fixture?secret=" + otpFixtureSeed + "&digits=8"

func otpFixture(t *testing.T) (string, []byte, RevealTarget) {
	t.Helper()
	path, key, target := revealFixture(t)
	revision, err := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "otp", Value: otpFixtureURI})
	if err != nil {
		t.Fatal(err)
	}
	target.Revision = revision
	return path, key, target
}

func TestOTPClockWindowsAndCleanup(t *testing.T) {
	path, key, target := otpFixture(t)
	for _, test := range []struct {
		name  string
		times []time.Time
		want  error
		from  int64
	}{
		{"valid", []time.Time{time.Unix(59, 100), time.Unix(59, 200), time.Unix(59, 300)}, nil, 30},
		{"expired", []time.Time{time.Unix(59, 100), time.Unix(59, 200), time.Unix(60, 0)}, ErrOTPTime, 0},
		{"same-window-backward", []time.Time{time.Unix(59, 100), time.Unix(59, 300), time.Unix(59, 200)}, ErrOTPTime, 0},
		{"during-commit-backward", []time.Time{time.Unix(59, 300), time.Unix(59, 100)}, ErrOTPTime, 0},
		{"negative", []time.Time{time.Unix(-1, 0), time.Unix(-1, 0)}, totp.ErrTime, 0},
		{"commit-crossed-window", []time.Time{time.Unix(59, 100), time.Unix(60, 0), time.Unix(60, 100)}, nil, 60},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			calls := 0
			clock := func() time.Time {
				if calls >= len(test.times) {
					t.Fatal("unexpected clock sample")
				}
				v := test.times[calls]
				calls++
				return v
			}
			var prepared result
			r, err := revealOTP(&output, clock, func() (result, error) {
				var err error
				prepared, err = command(path, "fixture", key, otpDisclosureAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision})
				return prepared, err
			})
			if !errors.Is(err, test.want) {
				t.Fatal("unexpected clock outcome", err)
			}
			if test.want != nil {
				if output.Len() != 0 || r != (OTPReceipt{}) {
					t.Fatal("invalid time disclosed")
				}
			} else if output.Len() == 0 || r.From != test.from || r.Until != test.from+30 {
				t.Fatal("wrong code window")
			}
			if prepared.otp == nil || prepared.otp.Parameters() != (totp.Parameters{}) {
				t.Fatal("temporary configuration not cleared")
			}
		})
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	intents := 0
	for _, event := range events {
		if event.Action == otpDisclosureAction {
			if event.Result != "intent" {
				t.Fatal("time failure changed committed intent")
			}
			intents++
		}
	}
	if intents != 6 {
		t.Fatal("lost time-failure intent")
	}
}

func TestOTPRollbackAndOutputFailures(t *testing.T) {
	path, key, target := otpFixture(t)
	var output bytes.Buffer
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected commit failure")
	clockCalls := 0
	_, err = revealOTP(&output, func() time.Time { clockCalls++; return time.Unix(59, 0) }, func() (result, error) {
		return commandWithUpdate(func(fn func(*bolt.Tx) error) error {
			return db.Update(func(tx *bolt.Tx) error {
				if err := fn(tx); err != nil {
					return err
				}
				return injected
			})
		}, "fixture", key, otpDisclosureAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision})
	})
	db.Close()
	if !errors.Is(err, injected) || output.Len() != 0 || clockCalls != 1 {
		t.Fatal("failed commit reached calculation/output", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == otpDisclosureAction {
			t.Fatal("rollback left intent")
		}
	}
	for _, short := range []bool{false, true} {
		writer := disclosureWriter(func(p []byte) (int, error) {
			if short {
				return len(p) - 1, nil
			}
			return 0, errors.New("94287082 " + otpFixtureSeed)
		})
		r, err := revealOTP(writer, func() time.Time { return time.Unix(59, 0) }, func() (result, error) {
			return command(path, "fixture", key, otpDisclosureAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision})
		})
		if !errors.Is(err, ErrDisclosureOutput) || r != (OTPReceipt{}) || strings.Contains(err.Error(), "94287082") || strings.Contains(err.Error(), otpFixtureSeed) {
			t.Fatal("output failure leaked or claimed success", err)
		}
	}
	events, err = Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	intents := 0
	for _, event := range events {
		if event.Action == otpDisclosureAction && event.Result == "intent" {
			intents++
		}
	}
	if intents != 2 {
		t.Fatal("output failure lost intent")
	}
	// Simulate an authenticated legacy/private writer storing an unsupported seed.
	r, err := command(path, "fixture", key, "item.add", vault.Item{Kind: "login", Title: "legacy OTP", Password: "synthetic-password", OTP: "MZXW6"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := List(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	revision := ""
	for _, row := range rows {
		if row.ID == r.id {
			revision = row.Revision
		}
	}
	if !digestOK(revision) {
		t.Fatal("missing legacy item revision")
	}
	if _, err = RevealOTP(path, "fixture", key, r.id, revision, &output); !errors.Is(err, totp.ErrInvalid) || output.Len() != 0 {
		t.Fatal("invalid saved configuration disclosed")
	}
}

func TestOTPConcurrentEditAndRecovery(t *testing.T) {
	path, key, target := otpFixture(t)
	var output bytes.Buffer
	var readErr, editErr error
	var revised string
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, readErr = revealOTP(&output, func() time.Time { return time.Unix(59, 0) }, func() (result, error) {
			return command(path, "fixture", key, otpDisclosureAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision})
		})
	}()
	go func() {
		defer wg.Done()
		revised, editErr = EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "otp", Value: "MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK"})
	}()
	wg.Wait()
	if editErr != nil {
		t.Fatal(editErr)
	}
	if readErr == nil {
		if output.String() != "\"94287082\"\r\n" {
			t.Fatal("concurrent read used wrong configuration")
		}
	} else if !errors.Is(readErr, ErrConflict) || output.Len() != 0 {
		t.Fatal("unexpected race result", readErr)
	}
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
	fresh := bytes.Repeat([]byte{8}, 16)
	if err = recovery.Publish(fresh); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if _, err = RevealOTP(restored, "fixture", fresh, target.ID, revised, &output); !errors.Is(err, ErrConflict) || output.Len() != 0 {
		t.Fatal("restore accepted old OTP revision", err)
	}
	rows, err := List(restored, "fixture", fresh)
	if err != nil {
		t.Fatal(err)
	}
	_, err = revealOTP(&output, func() time.Time { return time.Unix(59, 0) }, func() (result, error) {
		return command(restored, "fixture", fresh, otpDisclosureAction, vault.Item{}, &Edit{ID: target.ID, Revision: rows[0].Revision})
	})
	// Independent Python HMAC-SHA1 for seed "abcdefghijabcdefghij", counter 1.
	if err != nil || output.String() != "\"326399\"\r\n" {
		t.Fatal("recovered OTP wrong", err)
	}
	chains, err := ArchivedAudit(restored, "fixture", fresh)
	if err != nil {
		t.Fatal(err)
	}
	configEdits, requests := 0, 0
	for _, chain := range chains {
		for _, event := range chain.Events {
			if event.Action == "item.edit.otp" {
				configEdits++
			}
			if event.Action == otpDisclosureAction {
				requests++
			}
		}
	}
	if configEdits != 2 || requests != 1 {
		t.Fatal("OTP history lost or duplicated")
	}
}

func TestOTPIntentBeforeCalculationAndOutput(t *testing.T) {
	path, key, target := otpFixture(t)
	var out bytes.Buffer
	var intent Event
	clockCalls := 0
	clock := func() time.Time {
		clockCalls++
		if clockCalls == 2 {
			events, err := Audit(path, "fixture", key)
			if err != nil {
				t.Fatal(err)
			}
			intent = events[len(events)-2]
			if intent.Action != "item.reveal.otp-code" || intent.Result != "intent" || intent.BaseRevision != target.Revision {
				t.Fatal("calculation preceded durable intent")
			}
		}
		return time.Unix(59, 0)
	}
	r, err := revealOTP(&out, clock, func() (result, error) {
		return command(path, "fixture", key, "item.reveal.otp-code", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision})
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "\"94287082\"\r\n" || r.From != 30 || r.Until != 60 || r.Session != intent.Session || r.Intent != intent.hash() || r.Status != "written-to-terminal" {
		t.Fatal("incorrect RFC code, window or intent receipt")
	}
	rows, err := List(path, "fixture", key)
	if err != nil || rows[0].Revision != target.Revision {
		t.Fatal("OTP changed item revision", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal([]any{r, events, rows})
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{otpFixtureSeed, otpFixtureURI, "94287082"} {
		if bytes.Contains(public, []byte(secret)) || bytes.Contains(disk, []byte(secret)) {
			t.Fatal("OTP leaked outside terminal/encrypted field")
		}
	}
}

func TestOTPMissingStaleAndInvalidConfiguration(t *testing.T) {
	path, key, target := revealFixture(t)
	var out bytes.Buffer
	if _, err := RevealOTP(path, "fixture", key, target.ID, target.Revision, &out); !errors.Is(err, ErrOTPNotConfigured) || out.Len() != 0 {
		t.Fatal("missing OTP not rejected", err)
	}
	for _, value := range []string{"MZXW6", " ", "otpauth://totp/test?secret=" + otpFixtureSeed + "&unknown=1"} {
		if _, err := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "otp", Value: value}); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	revision, err := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "otp", Value: otpFixtureURI})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RevealOTP(path, "fixture", key, target.ID, target.Revision, &out); !errors.Is(err, ErrConflict) || out.Len() != 0 {
		t.Fatal("stale OTP revealed", err)
	}
	if _, err = RevealOTP(path, "wrong", key, target.ID, revision, &out); err == nil || out.Len() != 0 {
		t.Fatal("wrong factors revealed")
	}
	if _, err = RevealOTP(path, "fixture", key, strings.Repeat("a", 32), revision, &out); !errors.Is(err, ErrNotFound) || out.Len() != 0 {
		t.Fatal("unknown target revealed", err)
	}
	cleared, err := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: revision, Field: "otp", Value: ""})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RevealOTP(path, "fixture", key, target.ID, cleared, &out); !errors.Is(err, ErrOTPNotConfigured) || out.Len() != 0 {
		t.Fatal("cleared OTP still revealed", err)
	}
	if _, err = RevealLogin(path, "fixture", key, RevealTarget{target.ID, cleared, "otp-code"}, &out); err == nil {
		t.Fatal("raw reveal accepted OTP code")
	}
	if _, err = RevealLogin(path, "fixture", key, RevealTarget{target.ID, cleared, "otp"}, &out); err == nil {
		t.Fatal("raw reveal accepted seed")
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	var outcomes []string
	for _, event := range events {
		if event.Action == "item.reveal.otp-code" {
			outcomes = append(outcomes, event.Result)
		}
	}
	if strings.Join(outcomes, ",") != "not-configured,conflict,not-found,not-configured" {
		t.Fatal("incorrect OTP audit", outcomes)
	}
}
