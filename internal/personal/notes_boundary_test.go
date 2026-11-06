package personal

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

const notesBoundaryBodyMarker = "notes-boundary-current-canary"
const notesBoundarySourceMarker = "notes-boundary-import-canary"

type notesBoundaryFixture struct {
	s       *Session
	path    string
	key     []byte
	rev     string
	want    vault.Item
	context BrowserContext
}

func notesBoundaryOTPConfig(digits int) string {
	period := int64(3600)
	now := time.Now().Unix()
	for now%period > period-30 {
		period--
	}
	seed := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes.Repeat([]byte{19}, 20))
	return fmt.Sprintf("otpauth://totp/Boundary?secret=%s&period=%d&digits=%d", seed, period, digits)
}

func newNotesBoundaryFixture(t *testing.T) *notesBoundaryFixture {
	t.Helper()
	f := &notesBoundaryFixture{path: filepath.Join(t.TempDir(), "boundary.ll"), key: bytes.Repeat([]byte{23}, 16)}
	t.Cleanup(func() { clear(f.key) })
	if Create(f.path, "boundary-fixture", f.key) != nil {
		t.Fatal("boundary vault creation failed")
	}
	source, err := json.Marshal(map[string]string{"notesPlain": notesBoundarySourceMarker + "\noriginal source text", "username": "imported-user"})
	if err != nil {
		t.Fatal("boundary provenance construction failed")
	}
	f.want = vault.Item{Kind: "login", Title: "Boundary login", URL: "https://example.test/login", Username: "boundary-user", Password: "boundary-password", OTP: notesBoundaryOTPConfig(6), Notes: "  " + notesBoundaryBodyMarker + "\n第二行\t preserved  \n", ImportSource: source}
	added, err := command(f.path, "boundary-fixture", f.key, "item.add", f.want, nil)
	if err != nil {
		t.Fatal("boundary login creation failed")
	}
	f.want.ID = added.id
	f.s, err = UnlockSession(f.path, []byte("boundary-fixture"), f.key, time.Minute)
	if err != nil {
		t.Fatal("boundary vault unlock failed")
	}
	t.Cleanup(f.s.Lock)
	rows, err := f.s.List("active")
	if err != nil || len(rows) != 1 || rows[0].ID != f.want.ID {
		t.Fatal("boundary target unavailable")
	}
	f.rev = rows[0].Revision
	f.context = BrowserContext{RequestID: strings.Repeat("3", 32), Origin: "https://example.test", TabID: 1, DocumentID: "boundary-document"}
	notesBoundaryRetained(t, f)
	return f
}

// Use the production read-only authentication path, including history and
// snapshot validation, so a missing value cannot masquerade as a safe DTO.
func notesBoundaryRead(t *testing.T, f *notesBoundaryFixture) vault.Item {
	t.Helper()
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	var item vault.Item
	err := f.s.readNativeTarget(f.want.ID, f.rev, func(got vault.Item) error {
		item = got
		item.ImportSource = bytes.Clone(got.ImportSource)
		return nil
	})
	if err != nil {
		t.Fatal("boundary authenticated read failed")
	}
	return item
}

func notesBoundaryRetained(t *testing.T, f *notesBoundaryFixture) vault.Item {
	t.Helper()
	got := notesBoundaryRead(t, f)
	if got.Notes != f.want.Notes || !bytes.Equal(got.ImportSource, f.want.ImportSource) {
		t.Fatal("unrelated operation changed notes or original provenance")
	}
	return got
}

func notesBoundaryNoBody(t *testing.T, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("boundary DTO serialization failed")
	}
	defer clear(raw)
	var decoded any
	if json.Unmarshal(raw, &decoded) != nil {
		t.Fatal("boundary DTO decoding failed")
	}
	var check func(any)
	check = func(v any) {
		switch value := v.(type) {
		case map[string]any:
			for key, field := range value {
				if strings.EqualFold(key, "notes") || strings.EqualFold(key, "ImportSource") {
					t.Fatal("non-secret DTO exposed a body field")
				}
				check(field)
			}
		case []any:
			for _, field := range value {
				check(field)
			}
		case string:
			if strings.Contains(value, notesBoundaryBodyMarker) || strings.Contains(value, notesBoundarySourceMarker) {
				t.Fatal("non-secret DTO exposed a private body")
			}
		}
	}
	check(decoded)
}

func notesBoundaryError(t *testing.T, err error) {
	t.Helper()
	if err == nil || strings.Contains(err.Error(), notesBoundaryBodyMarker) || strings.Contains(err.Error(), notesBoundarySourceMarker) {
		t.Fatal("notes rejection was absent or exposed a private body")
	}
}

func notesBoundaryGate(t *testing.T, s *Session) *MutationGate {
	t.Helper()
	g := NewMutationGate(time.Now().Add(time.Minute))
	if s.RegisterMutation(g) != nil {
		t.Fatal("boundary mutation registration failed")
	}
	return g
}

func notesBoundaryRunRequest(t *testing.T) RunRequest {
	t.Helper()
	program, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	return RunRequest{Program: program, Directory: t.TempDir(), Name: "LOCKLARK_NOTES_BOUNDARY", TimeoutSeconds: 5}
}

func TestNotesBoundarySharedScopeGuards(t *testing.T) {
	target := RevealTarget{ID: strings.Repeat("1", 32), Revision: strings.Repeat("2", 64), Field: "notes"}
	for _, field := range []string{"username", "password"} {
		if !ValidRevealTarget(target.ID, target.Revision, field) {
			t.Fatal("existing shared disclosure field was removed")
		}
	}
	if ValidRevealTarget(target.ID, target.Revision, target.Field) {
		t.Fatal("notes entered the shared disclosure scope")
	}
	t.Run("terminal", func(t *testing.T) {
		var out bytes.Buffer
		prepared := false
		receipt, err := revealLogin(target, &out, func() (result, error) {
			prepared = true
			return result{}, nil
		})
		if err == nil || prepared || out.Len() != 0 || receipt != (DisclosureReceipt{}) {
			t.Fatal("terminal disclosure accepted notes")
		}
	})
	t.Run("inject", func(t *testing.T) {
		prepared, published := false, false
		receipt, err := injectJSON(target, "VALUE", filepath.Join(t.TempDir(), "output.json"), func(*injectionRequest) (result, error) {
			prepared = true
			return result{}, nil
		}, func([]byte, string) error { published = true; return nil })
		if err == nil || prepared || published || receipt != (InjectionReceipt{}) {
			t.Fatal("JSON injection accepted notes")
		}
	})
	t.Run("run", func(t *testing.T) {
		prepared, executed := false, false
		receipt, err := runEnv(context.Background(), target, notesBoundaryRunRequest(t), func(*RunRequest) (result, error) {
			prepared = true
			return result{}, nil
		}, func(context.Context, RunRequest, []byte) (int, error) { executed = true; return 0, nil })
		if err == nil || prepared || executed || receipt != (RunReceipt{}) {
			t.Fatal("process disclosure accepted notes")
		}
	})
}

func TestNotesBoundaryAuthenticatedSharedAPIsRejectNotes(t *testing.T) {
	f := newNotesBoundaryFixture(t)
	target := RevealTarget{ID: f.want.ID, Revision: f.rev, Field: "notes"}
	var out bytes.Buffer
	defer func() { clear(out.Bytes()) }()
	control := target
	control.Field = "password"
	if _, err := RevealLogin(f.path, "boundary-fixture", f.key, control, &out); err != nil {
		t.Fatal("existing password disclosure control failed")
	}
	var decoded string
	if json.Unmarshal(bytes.TrimSpace(out.Bytes()), &decoded) != nil || decoded != f.want.Password {
		t.Fatal("existing password disclosure returned the wrong field")
	}
	clear(out.Bytes())
	out.Reset()
	receipt, err := RevealLogin(f.path, "boundary-fixture", f.key, target, &out)
	notesBoundaryError(t, err)
	if out.Len() != 0 || receipt != (DisclosureReceipt{}) {
		t.Fatal("shared terminal API delivered notes")
	}
	dest := filepath.Join(t.TempDir(), "unexpected.json")
	injected, err := InjectJSON(f.path, "boundary-fixture", f.key, target, "VALUE", dest)
	notesBoundaryError(t, err)
	if _, statErr := os.Lstat(dest); !os.IsNotExist(statErr) || injected != (InjectionReceipt{}) {
		t.Fatal("shared injection API published notes")
	}
	marker := filepath.Join(t.TempDir(), "process-started")
	request := notesBoundaryRunRequest(t)
	request.Args = []string{"-test.run=^TestNotesBoundaryUnexpectedRunChild$", "--", marker}
	ran, err := RunEnv(context.Background(), f.path, "boundary-fixture", f.key, target, request)
	notesBoundaryError(t, err)
	if _, statErr := os.Lstat(marker); !os.IsNotExist(statErr) || ran != (RunReceipt{}) {
		t.Fatal("shared process API delivered notes")
	}
	index, err := References(f.path, "boundary-fixture", f.key)
	if err != nil || len(index.Items) != 1 || index.Items[0].ID != f.want.ID {
		t.Fatal("authenticated reference index unavailable")
	}
	if _, ok := index.Items[0].References["notes"]; ok || len(index.Items[0].References) != 3 {
		t.Fatal("notes entered the shared reference catalog")
	}
	notesBoundaryNoBody(t, index)
	raw := "op://" + index.VaultID + "/" + f.want.ID + "/notes"
	referenced, err := RevealReference(f.path, "boundary-fixture", f.key, raw, f.rev, &out)
	notesBoundaryError(t, err)
	if out.Len() != 0 || referenced != (DisclosureReceipt{}) {
		t.Fatal("shared reference disclosure delivered notes")
	}
	otp, err := RevealOTPReference(f.path, "boundary-fixture", f.key, raw, f.rev, &out)
	notesBoundaryError(t, err)
	if out.Len() != 0 || otp != (OTPReceipt{}) {
		t.Fatal("OTP reference disclosure delivered notes")
	}
	notesBoundaryRetained(t, f)
}

// RunEnv connects child output to the null device. A side effect proves that
// a regression actually started the process without printing its environment.
func TestNotesBoundaryUnexpectedRunChild(t *testing.T) {
	if os.Getenv("LOCKLARK_NOTES_BOUNDARY") == "" || len(os.Args) < 2 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	if os.WriteFile(os.Args[len(os.Args)-1], []byte("executed"), 0600) != nil {
		t.Fatal("unexpected child marker could not be written")
	}
}

func TestNotesBoundaryNonSecretViewsExcludeBodies(t *testing.T) {
	f := newNotesBoundaryFixture(t)
	listed, err := f.s.List("active")
	if err != nil || len(listed) != 1 {
		t.Fatal("authenticated list unavailable")
	}
	notesBoundaryNoBody(t, listed)
	searched, err := f.s.Search("Boundary", "active")
	if err != nil || len(searched) != 1 {
		t.Fatal("authenticated title search unavailable")
	}
	notesBoundaryNoBody(t, searched)
	for _, query := range []string{notesBoundaryBodyMarker, notesBoundarySourceMarker} {
		rows, err := f.s.Search(query, "all")
		if err != nil || len(rows) != 0 {
			t.Fatal("title search inspected a private body")
		}
	}
	review, err := f.s.ReviewNativeLogin(f.want.ID, f.rev)
	if err != nil || review.ID != f.want.ID {
		t.Fatal("native metadata review unavailable")
	}
	notesBoundaryNoBody(t, review)
	candidates, err := f.s.BrowserMatch(f.context)
	if err != nil || len(candidates) != 1 || candidates[0].ID != f.want.ID {
		t.Fatal("browser candidates unavailable")
	}
	notesBoundaryNoBody(t, candidates)
	health, err := f.s.Health()
	if err != nil || health.Checked != 1 {
		t.Fatal("native health report unavailable")
	}
	notesBoundaryNoBody(t, health)
	cliSearch, err := Search(f.path, "boundary-fixture", f.key, "Boundary", "active")
	if err != nil || len(cliSearch.Rows) != 1 {
		t.Fatal("shared search receipt unavailable")
	}
	notesBoundaryNoBody(t, cliSearch)
	cliHealth, err := Health(f.path, "boundary-fixture", f.key)
	if err != nil || cliHealth.Report.Checked != 1 {
		t.Fatal("shared health receipt unavailable")
	}
	notesBoundaryNoBody(t, cliHealth)
	events, err := f.s.Audit()
	if err != nil {
		t.Fatal("authenticated audit unavailable")
	}
	notesBoundaryNoBody(t, events)
	notesBoundaryRetained(t, f)
}

func TestNotesBoundaryBrowserOutputsKeepTheirExistingScope(t *testing.T) {
	f := newNotesBoundaryFixture(t)
	fill, err := f.s.PrepareBrowserFill(BrowserFillTarget{ID: f.want.ID, Revision: f.rev, Context: f.context})
	if err != nil {
		t.Fatal("browser fill preparation failed")
	}
	defer f.s.DiscardBrowserFill(fill)
	if raw, err := json.Marshal(fill); err == nil || len(raw) != 0 {
		clear(raw)
		t.Fatal("browser fill holder became serializable")
	}
	called, correct := false, false
	if f.s.ConsumeBrowserFill(fill, func(user, password []byte) error {
		called = true
		correct = string(user) == f.want.Username && string(password) == f.want.Password
		return nil
	}) != nil || !called || !correct {
		t.Fatal("browser fill changed its field scope")
	}
	control := NewBrowserOTPControl(time.Now().Add(5 * time.Second))
	defer control.Cancel()
	target := BrowserOTPTarget{ID: f.want.ID, Revision: f.rev, Context: BrowserOTPContext{BrowserContext: f.context, WindowID: 1}, ProfileVersion: 1}
	prepared, err := f.s.PrepareBrowserOTP(target, notesBoundaryGate(t, f.s), control)
	if err != nil {
		t.Fatal("browser OTP preparation failed")
	}
	defer f.s.DiscardBrowserOTP(prepared)
	delivery, err := f.s.AuthorizeBrowserOTP(prepared)
	if err != nil {
		t.Fatal("browser OTP authorization failed")
	}
	defer f.s.DiscardBrowserOTPDelivery(delivery)
	for _, holder := range []any{control, prepared, delivery} {
		if raw, err := json.Marshal(holder); err == nil || len(raw) != 0 {
			clear(raw)
			t.Fatal("browser OTP holder became serializable")
		}
	}
	output, err := f.s.GrantBrowserOTP(delivery)
	if err != nil {
		t.Fatal("browser OTP grant failed")
	}
	defer output.Clear()
	called, correct = false, false
	if output.Consume(func(code []byte, bounds OTPBounds) error {
		called = true
		correct = len(code) == 6 && bounds.Check(time.Now())
		for _, digit := range code {
			correct = correct && digit >= '0' && digit <= '9'
		}
		return nil
	}) != nil || !called || !correct {
		t.Fatal("browser OTP output changed its field scope")
	}
	notesBoundaryRetained(t, f)
	events, err := f.s.Audit()
	if err != nil {
		t.Fatal("browser output audit unavailable")
	}
	notesBoundaryNoBody(t, events)
}

func TestNotesBoundaryUnrelatedMutationsRetainNotesAndImportSource(t *testing.T) {
	f := newNotesBoundaryFixture(t)
	updatedNotes := "  " + notesBoundaryBodyMarker + " edited\n新正文\n"
	revision, err := f.s.SaveNativeNotes(f.want.ID, f.rev, []byte(updatedNotes), notesBoundaryGate(t, f.s))
	if err != nil {
		t.Fatal("native notes edit failed")
	}
	f.rev, f.want.Notes = revision, updatedNotes
	notesBoundaryRetained(t, f)
	target := BrowserSaveTarget{ID: f.want.ID, Revision: f.rev, Context: BrowserSaveContext{BrowserContext: f.context, WindowID: 1}}
	saved, err := f.s.SaveBrowser(target, []byte("browser-user"), []byte("browser-password"), notesBoundaryGate(t, f.s))
	if err != nil || saved.ID != f.want.ID || !digestOK(saved.Revision) {
		t.Fatal("browser save update failed")
	}
	f.rev = saved.Revision
	f.want.Username, f.want.Password = "browser-user", "browser-password"
	notesBoundaryNoBody(t, saved)
	got := notesBoundaryRetained(t, f)
	if got.Username != f.want.Username || got.Password != f.want.Password {
		t.Fatal("browser save control fields did not change")
	}
	revision, err = EditLogin(f.path, "boundary-fixture", f.key, Edit{ID: f.want.ID, Revision: f.rev, Field: "password", Value: "replacement-password"})
	if err != nil {
		t.Fatal("shared password edit failed")
	}
	f.rev, f.want.Password = revision, "replacement-password"
	if got := notesBoundaryRetained(t, f); got.Password != f.want.Password {
		t.Fatal("password edit control field did not change")
	}
	config := notesBoundaryOTPConfig(8)
	revision, err = f.s.Edit(Edit{ID: f.want.ID, Revision: f.rev, Field: "otp", Value: config})
	if err != nil {
		t.Fatal("OTP configuration edit failed")
	}
	f.rev, f.want.OTP = revision, config
	if got := notesBoundaryRetained(t, f); got.OTP != f.want.OTP {
		t.Fatal("OTP edit control field did not change")
	}
	generated, err := f.s.RegenerateNativePassword(f.want.ID, f.rev, 24, notesBoundaryGate(t, f.s))
	if err != nil || generated.ID != f.want.ID {
		t.Fatal("native password regeneration failed")
	}
	f.rev = generated.Revision
	notesBoundaryNoBody(t, generated)
	got = notesBoundaryRetained(t, f)
	if len(got.Password) != 24 || got.Password == f.want.Password {
		t.Fatal("password regeneration control field did not change")
	}
	f.want.Password = got.Password
	generated, err = RegeneratePassword(f.path, "boundary-fixture", f.key, f.want.ID, f.rev, 22)
	if err != nil || generated.ID != f.want.ID {
		t.Fatal("shared password regeneration failed")
	}
	f.rev = generated.Revision
	notesBoundaryNoBody(t, generated)
	if got := notesBoundaryRetained(t, f); len(got.Password) != 22 || got.Password == f.want.Password {
		t.Fatal("shared password regeneration control field did not change")
	}
}
