package personal

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jihuayu/locklark/internal/onepux"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func importArchive(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, file := range [][2]string{{"export.attributes", `{"version":3,"description":"1Password Unencrypted Export","createdAt":0}`}, {"export.data", `{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[{"uuid":"first","categoryUuid":"001","state":"active","overview":{"title":"private-title","url":"https://example.test"},"details":{"loginFields":[{"designation":"password","type":"P","value":"private-value"}]}},{"uuid":"second","categoryUuid":"001","state":"archived","overview":{"title":"private-title"},"details":{"loginFields":[{"designation":"username","type":"T","value":"private-user"},{"designation":"password","type":"P","value":""}]}}]}]}]}`}} {
		f, e := z.Create(file[0])
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write([]byte(file[1])); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func importFixture(t *testing.T) (string, []byte, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "owner.ll")
	source := filepath.Join(dir, "private.1pux")
	key := bytes.Repeat([]byte{4}, 16)
	if e := Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	raw := importArchive(t)
	if e := os.WriteFile(source, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return path, key, source, raw
}
func TestImportAtomicReceiptAndRecovery(t *testing.T) {
	path, key, source, raw := importFixture(t)
	plan, e := PlanImportOnepux(path, "fixture", key, source)
	if e != nil {
		t.Fatal(e)
	}
	publicHash := sha256.Sum256(raw)
	if plan.Report.SourceDigest == hex.EncodeToString(publicHash[:]) {
		t.Fatal("plan exposes an unkeyed source fingerprint")
	}
	other := filepath.Join(t.TempDir(), "other.ll")
	if e := Create(other, "fixture", key); e != nil {
		t.Fatal(e)
	}
	if _, e := ImportOnepux(other, "fixture", key, source, plan.Report.SourceDigest); !errors.Is(e, ErrImportChanged) {
		t.Fatal("plan accepted by a different vault", e)
	}
	if items := readStoredItems(t, path, "fixture", key); len(items) != 0 {
		t.Fatal("plan mutated items")
	}
	receipt, e := ImportOnepux(path, "fixture", key, source, plan.Report.SourceDigest)
	if e != nil {
		t.Fatal(e)
	}
	want, e := onepux.MapLogins(raw)
	if e != nil {
		t.Fatal(e)
	}
	if got := readStoredItems(t, path, "fixture", key); !reflect.DeepEqual(got, want.Items) {
		t.Fatal("not exact mapping")
	}
	if receipt.ReportDigest != plan.ReportDigest || receipt.Status != "imported-login-v1" {
		t.Fatal("receipt mismatch")
	}
	rows, e := ListState(path, "fixture", key, "all")
	if e != nil || len(rows) != 2 {
		t.Fatal("revisions missing", e)
	}
	for _, row := range rows {
		if !digestOK(row.Revision) {
			t.Fatal("invalid revision")
		}
	}
	before := readStoredItems(t, path, "fixture", key)
	if got, e := ImportOnepux(path, "fixture", key, source, plan.Report.SourceDigest); !errors.Is(e, ErrImportDuplicate) || !reflect.DeepEqual(got, ImportReceipt{}) {
		t.Fatal("duplicate import", e)
	}
	if !reflect.DeepEqual(before, readStoredItems(t, path, "fixture", key)) {
		t.Fatal("duplicate changed data")
	}
	events, e := Audit(path, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, ev := range events {
		if ev.Action == "item.import" {
			count++
			if ev.ReportDigest != receipt.ReportDigest {
				t.Fatal("unbound batch")
			}
		}
		if ev.Action == importAction && ev.Result == "succeeded" && ev.hash() != receipt.Event {
			t.Fatal("receipt event mismatch")
		}
	}
	if count != 2 {
		t.Fatal("per-item audit missing")
	}
	encoded, _ := json.Marshal([]any{plan, receipt, events})
	if strings.Contains(string(encoded), "private-") {
		t.Fatal("source leaked into receipt/audit")
	}
	backup := filepath.Join(t.TempDir(), "backup.ll")
	prep, e := PrepareBackup(path, backup, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	defer prep.Close()
	material := prep.Material()
	if e = prep.Publish(); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(t.TempDir(), "restored.ll")
	fresh := bytes.Repeat([]byte{8}, 16)
	e = Restore(backup, dest, "fixture", key, material, fresh)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(fresh)
	if !reflect.DeepEqual(before, readStoredItems(t, dest, "fixture", fresh)) {
		t.Fatal("recovery lost provenance")
	}
	recovered, e := ListState(dest, "fixture", fresh, "all")
	if e != nil || len(recovered) != 2 || recovered[0].Revision == rows[0].Revision {
		t.Fatal("recovery revision", e)
	}
	if _, e := ImportOnepux(dest, "fixture", fresh, source, plan.Report.SourceDigest); !errors.Is(e, ErrImportChanged) {
		t.Fatal("pre-recovery plan survived key replacement", e)
	}
}

func TestImportSourceBoundaryAndRollback(t *testing.T) {
	path, key, source, raw := importFixture(t)
	planned, e := PlanImportOnepux(path, "fixture", key, source)
	if e != nil {
		t.Fatal(e)
	}
	for _, badPassword := range []bool{true, false} {
		calls := 0
		pw := "fixture"
		if badPassword {
			pw = "wrong"
		} else {
			db, e := existing(path)
			if e != nil {
				t.Fatal(e)
			}
			e = db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put(tipKey, []byte("broken")) })
			db.Close()
			if e != nil {
				t.Fatal(e)
			}
		}
		_, e = command(path, pw, key, importAction, vault.Item{}, nil, commandOption{migration: &importRequest{expected: planned.Report.SourceDigest, read: func() ([]byte, error) { calls++; return bytes.Clone(raw), nil }}})
		if e == nil || calls != 0 {
			t.Fatal("unauthenticated source read")
		}
	}
	path, key, source, raw = importFixture(t)
	planned, e = PlanImportOnepux(path, "fixture", key, source)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := ImportOnepux(path, "fixture", key, source, strings.Repeat("0", 64)); !errors.Is(e, ErrImportChanged) || !reflect.DeepEqual(got, ImportReceipt{}) {
		t.Fatal("changed source accepted", e)
	}
	db, e := existing(path)
	if e != nil {
		t.Fatal(e)
	}
	injected := errors.New("injected")
	r, e := commandWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if e := fn(tx); e != nil {
				return e
			}
			return injected
		})
	}, "fixture", key, importAction, vault.Item{}, nil, commandOption{migration: &importRequest{expected: planned.Report.SourceDigest, read: func() ([]byte, error) { return bytes.Clone(raw), nil }}})
	db.Close()
	if !errors.Is(e, injected) || !reflect.DeepEqual(r, result{}) {
		t.Fatal("rollback receipt", e)
	}
	if len(readStoredItems(t, path, "fixture", key)) != 0 {
		t.Fatal("partial import after rollback")
	}
	events, e := Audit(path, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	for _, ev := range events {
		if ev.Action == "item.import" {
			t.Fatal("rollback retained item audit")
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for j := 0; j < 2; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ImportOnepux(path, "fixture", key, source, planned.Report.SourceDigest)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	successes, duplicates := 0, 0
	for err := range errs {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrImportDuplicate) {
			duplicates++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || duplicates != 1 {
		t.Fatal("concurrent import did not serialize")
	}
}
