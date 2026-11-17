package personal

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/onepux"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func TestNativeNotesExplicitEditIntent(t *testing.T) {
	s, target := browserFixture(t)
	f, e := s.PrepareField(RevealTarget{ID: target.ID, Revision: target.Revision, Field: "notes"}, "edit")
	if e != nil {
		t.Fatal("native explicit notes edit preparation refused")
	}
	defer s.Discard(f)
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, event := range events {
		if event.Action == "item.desktop.edit.notes" && event.Result == "intent" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing notes edit disclosure intent")
	}
}

func TestNativeNotesSaveDisclosureAndLifecycle(t *testing.T) {
	s, target := browserFixture(t)
	body := []byte(" first\r\n备注\t🙂\nlast  ")
	want := bytes.Clone(body)
	rev, e := s.SaveNativeNotes(target.ID, target.Revision, body, dailyGate(t, s))
	if e != nil || rev == target.Revision || !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("notes save/revision/buffer ownership failed", e)
	}
	for _, purpose := range []string{"show", "copy", "edit"} {
		field, e := s.PrepareField(RevealTarget{ID: target.ID, Revision: rev, Field: "notes"}, purpose)
		if e != nil {
			t.Fatal(e)
		}
		called := 0
		e = s.Consume(field, func(value []byte) error {
			called++
			if !bytes.Equal(value, want) || bytes.Equal(value, []byte("fixture-user")) {
				t.Fatal("notes selector did not return exact notes")
			}
			return nil
		})
		if e != nil || called != 1 || s.Consume(field, func([]byte) error { t.Fatal("notes native field reused"); return nil }) == nil {
			t.Fatal("notes disclosure not single use")
		}
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	found := map[string]bool{}
	for _, event := range events {
		if desktopFieldAction(event.Action) && strings.HasSuffix(event.Action, ".notes") {
			if event.Result != "intent" || event.BaseRevision != rev {
				t.Fatal("wrong notes intent/revision")
			}
			found[event.Action] = true
		}
	}
	if len(found) != 3 {
		t.Fatal("missing exact notes intents")
	}
	// Cancel wins before any item or refusal-audit persistence.
	before := dailyDiskState(t, s.path)
	g := dailyGate(t, s)
	g.Cancel()
	if _, e = s.SaveNativeNotes(target.ID, rev, []byte("cancelled"), g); !errors.Is(e, ErrMutationCancelled) || !bytes.Equal(before, dailyDiskState(t, s.path)) {
		t.Fatal("cancelled notes persisted", e)
	}
	if _, e = s.SaveNativeNotes(target.ID, target.Revision, []byte("stale"), dailyGate(t, s)); !errors.Is(e, ErrConflict) {
		t.Fatal("stale notes overwrote target", e)
	}
	for _, value := range []string{strings.Repeat("x", vault.MaxNotes+1), "invalid\x00body", "\xff"} {
		g = dailyGate(t, s)
		if _, e = s.SaveNativeNotes(target.ID, rev, []byte(value), g); !errors.Is(e, ErrMutationRefused) || !g.CommitWon() {
			t.Fatal("known invalid notes did not commit fixed refusal", e)
		}
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		if row.ID == target.ID && row.Revision != rev {
			t.Fatal("notes refusal changed revision")
		}
	}
	rev, e = s.SaveNativeNotes(target.ID, rev, []byte(strings.Repeat("x", vault.MaxNotes)), dailyGate(t, s))
	if e != nil {
		t.Fatal("exact 64KiB native notes rejected", e)
	}
	archived, e := s.SetState(target.ID, rev, "item.archive")
	if e != nil {
		t.Fatal(e)
	}
	cleared, e := s.SaveNativeNotes(target.ID, archived, nil, dailyGate(t, s))
	if e != nil {
		t.Fatal("archived notes clear refused", e)
	}
	f, e := s.PrepareField(RevealTarget{ID: target.ID, Revision: cleared, Field: "notes"}, "show")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Consume(f, func(value []byte) error {
		if len(value) != 0 {
			t.Fatal("empty notes did not clear")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	trashed, e := s.SetState(target.ID, cleared, "item.trash")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.SaveNativeNotes(target.ID, trashed, []byte("blocked"), dailyGate(t, s)); !errors.Is(e, ErrTrashed) {
		t.Fatal("trashed notes edit allowed", e)
	}
	if _, e = s.PrepareField(RevealTarget{ID: target.ID, Revision: trashed, Field: "notes"}, "copy"); !errors.Is(e, ErrTrashed) {
		t.Fatal("trashed notes disclosure allowed", e)
	}
}

func TestNativeNotesConcurrentEditorsHaveOneWinner(t *testing.T) {
	fixture := newNotesBoundaryFixture(t)
	s := fixture.s
	originalNotes := fixture.want.Notes
	target := RevealTarget{ID: fixture.want.ID, Revision: fixture.rev, Field: "notes"}
	other, e := UnlockSession(s.path, []byte("boundary-fixture"), fixture.key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Lock()
	gates := []*MutationGate{dailyGate(t, s), dailyGate(t, other)}
	sessions := []*Session{s, other}
	start := make(chan struct{})
	errs := make([]error, 2)
	revs := make([]string, 2)
	var workers sync.WaitGroup
	for i := range sessions {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			revs[i], errs[i] = sessions[i].SaveNativeNotes(target.ID, target.Revision, []byte("editor "+string(rune('A'+i))), gates[i])
		}(i)
	}
	close(start)
	workers.Wait()
	wins, conflicts := 0, 0
	winner := -1
	for i, e := range errs {
		if e == nil && digestOK(revs[i]) {
			wins++
			winner = i
		} else if errors.Is(e, ErrConflict) && revs[i] == "" {
			conflicts++
		} else {
			t.Fatal("unexpected concurrent notes edit outcome", e)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("concurrent notes editors did not have one winner")
	}
	fixture.rev = revs[winner]
	actual := notesBoundaryRead(t, fixture)
	if actual.Notes != "editor "+string(rune('A'+winner)) {
		t.Fatal("stored notes do not match committed editor")
	}
	if len(actual.History) != 1 || actual.History[0].Notes != originalNotes || actual.History[0].Password != fixture.want.Password || actual.History[0].Action != "edit" {
		t.Fatalf("notes edit history: %+v", actual.History)
	}
	actual.Notes = fixture.want.Notes
	actual.History = nil
	if !reflect.DeepEqual(actual, fixture.want) {
		t.Fatal("notes edit changed another field or original import source")
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	counts := map[string]int{}
	for _, event := range events {
		if event.Action == "item.edit.notes" {
			counts[event.Result]++
		}
	}
	if counts["succeeded"] != 1 || counts["conflict"] != 1 {
		t.Fatal("concurrent notes audit mismatch")
	}
}

func TestNativeNotesBackupRestoreRetainsValuesSourceAndHistory(t *testing.T) {
	f := newNotesBoundaryFixture(t)
	s := f.s
	field, e := s.PrepareField(RevealTarget{ID: f.want.ID, Revision: f.rev, Field: "notes"}, "edit")
	if e != nil {
		t.Fatal(e)
	}
	s.Discard(field)
	originalNotes := f.want.Notes
	f.rev, e = s.SaveNativeNotes(f.want.ID, f.rev, []byte("edited\r\n备注🙂  "), dailyGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	f.want.Notes = "edited\r\n备注🙂  "
	archive := filepath.Join(t.TempDir(), "notes-backup.llb")
	kit, e := Backup(f.path, archive, "boundary-fixture", f.key)
	if e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(t.TempDir(), "notes-restored.ll")
	key := bytes.Repeat([]byte{11}, 16)
	if e = Restore(archive, dest, "boundary-fixture", f.key, kit, key); e != nil {
		t.Fatal(e)
	}
	got := readStoredItems(t, dest, "boundary-fixture", key)
	if len(got) != 1 || len(got[0].History) != 1 || got[0].History[0].Notes != originalNotes || got[0].History[0].Password != f.want.Password || got[0].History[0].Action != "edit" {
		t.Fatalf("notes backup lost history: %+v", got)
	}
	got[0].History = nil
	if !reflect.DeepEqual(got, []vault.Item{f.want}) {
		t.Fatal("notes backup lost values or original source")
	}
	chains, e := ArchivedAudit(dest, "boundary-fixture", key)
	if e != nil {
		t.Fatal("notes audit history failed recovery", e)
	}
	found := map[string]bool{}
	for _, chain := range chains {
		for _, event := range chain.Events {
			found[event.Action] = true
		}
	}
	if !found["item.desktop.edit.notes"] || !found["item.edit.notes"] {
		t.Fatal("notes recovery lost audit history")
	}
}

func TestNativeNotesPreparedExpiryLockAndExactFieldPurposes(t *testing.T) {
	s, target := browserFixture(t)
	for _, field := range []string{"username", "password"} {
		if _, e := s.PrepareField(RevealTarget{ID: target.ID, Revision: target.Revision, Field: field}, "edit"); e == nil {
			t.Fatal("edit purpose expanded beyond notes")
		}
	}
	field, e := s.PrepareField(RevealTarget{ID: target.ID, Revision: target.Revision, Field: "notes"}, "copy")
	if e != nil {
		t.Fatal(e)
	}
	field.until = time.Now().Add(-time.Second)
	if s.Consume(field, func([]byte) error { t.Fatal("expired notes delivered"); return nil }) == nil || field.value != nil {
		t.Fatal("expired notes not cleared")
	}
	field, e = s.PrepareField(RevealTarget{ID: target.ID, Revision: target.Revision, Field: "notes"}, "edit")
	if e != nil {
		t.Fatal(e)
	}
	s.RequestLock()
	if !errors.Is(s.Consume(field, func([]byte) error { t.Fatal("locked notes delivered"); return nil }), ErrSessionLocked) || field.value != nil {
		t.Fatal("locked notes not cleared")
	}
}

func TestNativeNotesMutationFaults(t *testing.T) {
	for _, fault := range []string{"rollback", "close-success", "close-refusal", "cancel-refusal"} {
		t.Run(fault, func(t *testing.T) {
			s, target := browserFixture(t)
			g := dailyGate(t, s)
			before := dailyDiskState(t, s.path)
			edit := &Edit{ID: target.ID, Revision: target.Revision, Field: "notes", Value: "notes\nbody"}
			if strings.HasSuffix(fault, "refusal") {
				edit.Revision = strings.Repeat("e", 64)
			}
			run := func(o commandOption) (result, error) {
				db, e := existing(s.path)
				if e != nil {
					return result{}, e
				}
				return commandWithClose(func() (result, error) {
					return commandWithUpdate(func(fn func(*bolt.Tx) error) error {
						return db.Update(func(tx *bolt.Tx) error {
							if fault == "cancel-refusal" {
								g.Cancel()
							}
							if e := fn(tx); e != nil {
								return e
							}
							if fault == "rollback" {
								return errors.New("fixed rollback")
							}
							return nil
						})
					}, "", nil, "item.edit.notes", vault.Item{}, edit, o)
				}, func() error {
					e := db.Close()
					if strings.HasPrefix(fault, "close") {
						return errors.New("fixed close failure")
					}
					return e
				})
			}
			_, e := s.nativeMutationWith("item.edit.notes", vault.Item{}, edit, commandOption{}, g, run)
			want := ErrMutationUnknown
			if fault == "cancel-refusal" {
				want = ErrMutationCancelled
			}
			if !errors.Is(e, want) {
				t.Fatal("notes mutation fault classification failed", e)
			}
			if fault == "rollback" || fault == "cancel-refusal" {
				if !bytes.Equal(before, dailyDiskState(t, s.path)) {
					t.Fatal("rolled-back/cancelled notes or refusal audit persisted")
				}
			}
		})
	}
}

func TestLoginNotesImportPlanDomainRejectsOldPlan(t *testing.T) {
	raw := importArchive(t)
	secret := bytes.Repeat([]byte{3}, 32)
	derived, e := hkdf.Key(sha256.New, secret, nil, "locklark/personal/import-plan/key/v1", 32)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(derived)
	mac := hmac.New(sha256.New, derived)
	mac.Write([]byte("locklark/personal/import-plan/login-v1\x00"))
	mac.Write(raw)
	old := hex.EncodeToString(mac.Sum(nil))
	request := &importRequest{read: func() ([]byte, error) { return bytes.Clone(raw), nil }, expected: old}
	if mapped, e := request.mapSource(secret); !errors.Is(e, ErrImportChanged) || !reflect.DeepEqual(mapped, onepux.MappedLogins{}) {
		t.Fatal("old plan domain still accepted", e)
	}
	request.expected = ""
	mapped, e := request.mapSource(secret)
	if e != nil || mapped.Report.SourceDigest == old || mapped.Report.Profile != "login-notes-v2" {
		t.Fatal("new notes plan domain missing", e)
	}
	request.expected = mapped.Report.SourceDigest
	if _, e = request.mapSource(secret); e != nil {
		t.Fatal("new plan could not be confirmed", e)
	}
}

func TestNativeNotesActionFieldMismatch(t *testing.T) {
	for _, pair := range [][2]string{{"item.desktop.show.password", "notes"}, {"item.desktop.show.notes", "username"}, {"item.desktop.copy.username", "notes"}, {"item.desktop.copy.notes", "password"}, {"item.desktop.edit.notes", "password"}, {"item.edit.notes", "password"}} {
		called := false
		_, e := commandWithUpdate(func(func(*bolt.Tx) error) error { called = true; return errors.New("unexpected transaction") }, "", nil, pair[0], vault.Item{}, &Edit{ID: strings.Repeat("a", 32), Revision: strings.Repeat("b", 64), Field: pair[1]})
		if called || !errors.Is(e, invalid) {
			t.Fatal("mismatched native action/field reached authenticated transaction")
		}
	}
}
