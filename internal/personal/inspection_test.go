package personal

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/onepux"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

type testInspectionFile struct {
	io.Reader
	info              fs.FileInfo
	statErr, closeErr error
	closed            int
}

func (f *testInspectionFile) Stat() (fs.FileInfo, error) { return f.info, f.statErr }
func (f *testInspectionFile) Close() error               { f.closed++; return f.closeErr }

type failedInspectionReader struct{}

func (failedInspectionReader) Read(p []byte) (int, error) {
	return copy(p, "private-partial"), errors.New("private-read-error")
}

func TestInspectionSourceAndCloseFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	private := errors.New("private-source-path")
	for _, f := range []*testInspectionFile{
		{Reader: bytes.NewReader([]byte("private")), info: info, closeErr: private},
		{Reader: failedInspectionReader{}, info: info},
		{Reader: bytes.NewReader(nil), statErr: private},
	} {
		data, err := readInspectionFile(f)
		if !errors.Is(err, ErrInspectionSource) || data != nil || f.closed != 1 || strings.Contains(err.Error(), "private") {
			t.Fatal("source I/O failure leaked", err)
		}
	}
	f := &testInspectionFile{Reader: bytes.NewReader(make([]byte, onepux.MaxArchive+1)), info: info}
	if data, err := readInspectionFile(f); !errors.Is(err, onepux.ErrLimit) || data != nil || f.closed != 1 {
		t.Fatal("source growth escaped limit", err)
	}
	if data, err := readInspectionSource(dir); !errors.Is(err, ErrInspectionSource) || data != nil {
		t.Fatal("directory accepted", err)
	}
	if err := os.Truncate(path, onepux.MaxArchive+1); err != nil {
		t.Fatal(err)
	}
	if data, err := readInspectionSource(path); !errors.Is(err, onepux.ErrLimit) || data != nil {
		t.Fatal("oversize source accepted", err)
	}
	// A committed operation is not allowed to release its report if DB close
	// subsequently fails. The error must not contain the writer's message.
	value := []byte("private-output")
	r, err := commandWithClose(func() (result, error) {
		return result{inspection: onepux.Report{Items: 1}, reportDigest: strings.Repeat("a", 64), session: "session", value: value}, nil
	}, func() error { return private })
	if !errors.Is(err, ErrCommandClose) || !reflect.DeepEqual(r, result{}) || strings.Contains(err.Error(), "private") || !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatal("database close failure released result", err)
	}
}

func TestInspectionDamagedJournalDoesNotReadSource(t *testing.T) {
	path, key, _ := revealFixture(t)
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put(tipKey, []byte("corrupt")) })
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err = command(path, "fixture", key, inspectionAction, vault.Item{}, nil, commandOption{inspection: &inspectionRequest{read: func() ([]byte, error) { calls++; return nil, nil }}})
	if err == nil || calls != 0 {
		t.Fatal("damaged journal reached source")
	}
}

func inspectionArchive(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, e := range []struct{ name, data string }{{"export.attributes", `{"version":3,"description":"1Password Unencrypted Export","createdAt":0}`}, {"export.data", `{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[{"uuid":"i","categoryUuid":"001","state":"active","overview":{"title":"private-title"},"details":{"loginFields":[{"designation":"password","fieldType":"P","value":"private-password"}],"passwordHistory":[{"value":"private-old","time":1}]}}]}]}]}`}} {
		f, err := w.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(e.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestInspectionReceiptAuditAndRecovery(t *testing.T) {
	path, key, _ := revealFixture(t)
	source := filepath.Join(t.TempDir(), "private-source.1pux")
	raw := inspectionArchive(t)
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	receipt, err := InspectOnepux(path, "fixture", key, source)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "inspected-unmapped" || receipt.Report.Items != 1 || receipt.Report.PasswordHistory.Entries != 1 || receipt.Report.MappingVerified {
		t.Fatal("wrong inspection result")
	}
	expected, _ := digest(receipt.Report)
	if receipt.ReportDigest != expected {
		t.Fatal("report digest mismatch")
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	e := events[len(events)-2]
	if e.Action != inspectionAction || e.Result != "succeeded" || e.ReportDigest != expected || e.Session != receipt.Session || e.hash() != receipt.Event || e.Item != "" || e.BaseRevision != "" {
		t.Fatal("receipt not tied to durable inspection event")
	}
	encoded, _ := json.Marshal([]any{receipt, events})
	if strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), source) {
		t.Fatal("inspection leaked source data")
	}
	after, _ := os.ReadFile(source)
	if !bytes.Equal(raw, after) {
		t.Fatal("source changed")
	}
	backup, err := PrepareBackup(path, filepath.Join(t.TempDir(), "backup.llb"), "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	kit := backup.Material()
	if err = backup.Publish(); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.ll")
	recovery, err := PrepareRestore(backup.dest, restored, "fixture", key, kit)
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	fresh := bytes.Repeat([]byte{8}, 16)
	if err = recovery.Publish(fresh); err != nil {
		t.Fatal(err)
	}
	chains, err := ArchivedAudit(restored, "fixture", fresh)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, c := range chains {
		for _, event := range c.Events {
			if event.hash() == receipt.Event && event.ReportDigest == expected {
				found++
			}
		}
	}
	if found != 1 {
		t.Fatal("restored audit lost inspection")
	}
}

func TestInspectionAuthenticationRollbackAndRefusals(t *testing.T) {
	path, key, _ := revealFixture(t)
	calls := 0
	request := &inspectionRequest{read: func() ([]byte, error) { calls++; return inspectionArchive(t), nil }}
	option := commandOption{inspection: request}
	if _, err := command(path, "wrong", key, inspectionAction, vault.Item{}, nil, option); err == nil || calls != 0 {
		t.Fatal("unauthenticated source access")
	}
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected commit failure")
	r, err := commandWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return injected
		})
	}, "fixture", key, inspectionAction, vault.Item{}, nil, option)
	db.Close()
	if !errors.Is(err, injected) || !reflect.DeepEqual(r.inspection, onepux.Report{}) || r.reportDigest != "" || r.session != "" || calls != 1 {
		t.Fatal("rollback returned report", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == inspectionAction {
			t.Fatal("rollback left inspection event")
		}
	}
	for _, test := range []struct {
		data      []byte
		err, want error
		result    string
	}{
		{[]byte("private-invalid"), nil, onepux.ErrInvalid, "invalid"},
		{nil, onepux.ErrLimit, onepux.ErrLimit, "limit"},
		{nil, onepux.ErrUnsupported, onepux.ErrUnsupported, "unsupported"},
		{[]byte("private-partial"), errors.New("private-path"), ErrInspectionSource, "source-error"},
	} {
		data := bytes.Clone(test.data)
		option.inspection = &inspectionRequest{read: func() ([]byte, error) { return data, test.err }}
		r, err := command(path, "fixture", key, inspectionAction, vault.Item{}, nil, option)
		if !errors.Is(err, test.want) || !reflect.DeepEqual(r.inspection, onepux.Report{}) || r.reportDigest != "" || strings.Contains(err.Error(), "private") {
			t.Fatal("invalid inspection refusal", err)
		}
		for _, b := range data {
			if b != 0 {
				t.Fatal("temporary source not cleared")
			}
		}
	}
	events, err = Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	var results []string
	for _, e := range events {
		if e.Action == inspectionAction {
			results = append(results, e.Result)
			if e.ReportDigest != "" || e.Item != "" || e.BaseRevision != "" {
				t.Fatal("refusal retained report/target")
			}
		}
	}
	if strings.Join(results, ",") != "invalid,limit,unsupported,source-error" {
		t.Fatal("wrong refusal events", results)
	}
}

func TestInspectionEventValidation(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	base := Event{Sequence: 2, UTC: time.Now().UTC().Format(time.RFC3339Nano), Session: strings.Repeat("a", 32), Actor: "local-owner", Action: inspectionAction, Result: "succeeded", Previous: strings.Repeat("b", 64), ReportDigest: strings.Repeat("c", 64)}
	verify := func(e Event) error {
		e.Signature = ed25519.Sign(private, e.proof())
		return e.verify(private.Public().(ed25519.PublicKey), 2, base.Previous)
	}
	if err := verify(base); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Event){func(e *Event) { e.ReportDigest = "" }, func(e *Event) { e.ReportDigest = "private" }, func(e *Event) { e.Action = "item.list" }, func(e *Event) { e.Result = "invalid" }, func(e *Event) { e.Item = strings.Repeat("d", 32) }, func(e *Event) { e.BaseRevision = strings.Repeat("d", 64) }, func(e *Event) { e.Link = strings.Repeat("d", 32) }} {
		e := base
		mutate(&e)
		if verify(e) == nil {
			t.Fatal("invalid inspection event accepted")
		}
	}
	for _, result := range []string{"invalid", "unsupported", "limit", "source-error"} {
		e := base
		e.Result = result
		e.ReportDigest = ""
		if err := verify(e); err != nil {
			t.Fatal(err)
		}
	}
}
