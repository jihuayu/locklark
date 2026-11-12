package vaultfilesync

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	bolt "go.etcd.io/bbolt"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/testtemp"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

func TestMain(m *testing.M) {
	// The journal and the directory backend refuse a non-private parent, and
	// on Windows that includes the whole ancestry of t.TempDir.
	testtemp.Main(m)
}

// The fixture is one published static policy (no secret), with per-test real
// crypto generated around it: an age X25519 identity for device-1, a real
// Ed25519 content-signing key and a real VUK.
const (
	remoteName        = "vault-01.locklark"
	fixtureDeviceID   = "device-1"
	fixtureRootPublic = "sdtT9ivuFVcIsKunv9utR5FqBWUY/CeCwbmdJKQdSB4="

	// fixtureIdentityToken is the age secret key of device-1.
	fixtureIdentityToken = "AGE-SECRET-KEY-14DWNGPVTKMZ7SDL5X02QFEJ3WJX4ZX9WCCYVS756GZU9QE4YGQPQXUCUVM"
	// fixtureSigningSeed is the Ed25519 seed of device-1's content signing key.
	fixtureSigningSeed = "ZUunmtd0EekyD0HODAQ5G4vMbpfkUTQDAJc5n4JEzRU="
	// fixturePolicyDocument is the canonical policy document (policy_seq 5,
	// alice writer/admin/owner with device-1), base64. It is not JSON: it is
	// the exact canonical document bytes carried by the signed proof.
	fixturePolicyDocument = "eyJmb3JtYXQiOiJsb2NrbGFyay52YXVsdC1maWxlIiwidmVyc2lvbiI6MSwidmF1bHRfaWQiOiJ2YXVsdC0wMSIsInBvbGljeV9zZXEiOjUsInByZXZfcG9saWN5X2RpZ2VzdCI6IkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkUiLCJvd25lcl9yb290Ijp7ImtleV9pZCI6Im93bmVyLXJvb3QtMDEiLCJhbGciOiJlZDI1NTE5IiwicHVibGljX2tleSI6InNkdFQ5aXZ1RlZjSXNLdW52OXV0UjVGcUJXVVlfQ2VDd2JtZEpLUWRTQjQiLCJvd25lcnMiOlt7InByaW5jaXBhbF9pZCI6ImFsaWNlIiwibGFiZWwiOiJBbGljZSJ9XX0sInJlYWRlcnMiOltdLCJ3cml0ZXJzIjpbeyJwcmluY2lwYWxfaWQiOiJhbGljZSIsImxhYmVsIjoiQWxpY2UifV0sImFkbWlucyI6W3sicHJpbmNpcGFsX2lkIjoiYWxpY2UiLCJsYWJlbCI6IkFsaWNlIn1dLCJvd25lcnMiOlt7InByaW5jaXBhbF9pZCI6ImFsaWNlIiwibGFiZWwiOiJBbGljZSJ9XSwiYWRtaW5fZGVsZWdhdGlvbnMiOltdLCJkZXZpY2VzIjpbeyJkZXZpY2VfaWQiOiJkZXZpY2UtMSIsInByaW5jaXBhbF9pZCI6ImFsaWNlIiwibGFiZWwiOiJBbGljZSBsYXB0b3AiLCJjb250ZW50X3NpZ25pbmdfa2V5Ijp7ImFsZyI6ImVkMjU1MTkiLCJwdWJsaWNfa2V5IjoicHBlUzJfNmdSTEtjTngzdk1FQkNWSnVQdTNSajA4d1VEZmhiZXQ0SUtWbyJ9LCJwb2xpY3lfc2lnbmluZ19rZXkiOm51bGwsImFnZV9lbmNyeXB0aW9uX2tleSI6ImFnZTFxcmh6bWp1cXJtN3hsdWh4eXp4bWFjeDJjZ2dncm11cm1zcHkwbWVtdmpzc2xtZzU3ZnFxdmhoMGxoIn1dfQ=="
)

// plaintextMarkers are values that must never appear in a receipt or an error.
var plaintextMarkers = []string{
	"synthetic-password", "synthetic-old-password", "synthetic notes",
	"synthetic-user", "synthetic-export", "synthetic attachment body",
	"synthetic legacy document body", "synthetic-metadata", "fixture.bin",
	"synthetic-user-handle",
}

// fixtureInputs returns the parsed static policy, device-1's age identity and
// device-1's content-signing key.
func fixtureInputs(t *testing.T) (*vaultfile.Policy, *age.X25519Identity, ed25519.PrivateKey) {
	t.Helper()
	doc, err := base64.StdEncoding.DecodeString(fixturePolicyDocument)
	if err != nil {
		t.Fatal(err)
	}
	p, err := vaultfile.ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("fixture policy: %v", err)
	}
	id, err := age.ParseX25519Identity(fixtureIdentityToken)
	if err != nil {
		t.Fatalf("fixture identity: %v", err)
	}
	seed, err := base64.StdEncoding.DecodeString(fixtureSigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	return p, id, ed25519.NewKeyFromSeed(seed)
}

// fixturePin returns the caller's trusted checkpoint for the static policy.
func fixturePin(t *testing.T, p *vaultfile.Policy) *vaultfile.PolicyCheckpoint {
	t.Helper()
	root, err := base64.StdEncoding.DecodeString(fixtureRootPublic)
	if err != nil {
		t.Fatal(err)
	}
	return &vaultfile.PolicyCheckpoint{
		VaultID:            p.VaultID,
		OwnerRootKeyID:     p.OwnerRoot.KeyID,
		OwnerRootPublicKey: root,
		PolicySeq:          p.PolicySeq,
		PolicyDigest:       vaultfile.PolicyDigest(p),
	}
}

// fixturePasskeyRecord is one real ES256 WebAuthn record built through the
// passkey package, with a fixed synthetic user handle.
func fixturePasskeyRecord(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	rec, err := json.Marshal(map[string]any{
		"version":      1,
		"id":           base64.RawURLEncoding.EncodeToString(id),
		"rp_id":        "example.com",
		"user_id":      base64.RawURLEncoding.EncodeToString([]byte("synthetic-user-handle")),
		"name":         "synthetic-user",
		"display_name": "Synthetic User",
		"private_key":  der,
	})
	if err != nil {
		t.Fatal(err)
	}
	clear(der)
	if !passkey.ValidRecord(rec) {
		t.Fatal("fixture passkey record is not a valid record")
	}
	return rec
}

// fixtureDraft is the builder File sealed with the static policy.
func fixtureDraft(t *testing.T, p *vaultfile.Policy) *vaultfile.File {
	t.Helper()
	doc, err := base64.StdEncoding.DecodeString(fixturePolicyDocument)
	if err != nil {
		t.Fatal(err)
	}
	return &vaultfile.File{
		Format:  vaultfile.Format,
		Version: vaultfile.Version,
		Header: vaultfile.Header{
			VaultID:        p.VaultID,
			KeyEpoch:       1,
			ContentSeq:     1,
			PrevDigest:     bytes.Repeat([]byte{0x22}, 32),
			OpID:           "op-0001",
			PolicySeq:      p.PolicySeq,
			PolicyDigest:   vaultfile.PolicyDigest(p),
			AuthorDeviceID: fixtureDeviceID,
		},
		SignedPolicyProofs: []vaultfile.SignedPolicy{{
			Document: doc,
			Policy:   *p,
			SignerID: p.OwnerRoot.KeyID,
			Alg:      vaultfile.PolicySigAlgEd25519,
			Sig:      make([]byte, ed25519.SignatureSize),
		}},
	}
}

// itemDatabase builds a real item database holding every kind of mutable
// plaintext buffer this package clears: a login with provenance, history and a
// passkey collection, a v2 attachment and a protected document attachment.
func itemDatabase(t *testing.T) *kdbx.Database {
	t.Helper()
	attContent := []byte("synthetic attachment body\x00\xff")
	items := []vault.Item{
		{
			ID: "login-1", Kind: "login", Title: "Example login",
			Username: "synthetic-user", Password: "synthetic-password",
			URL: "https://example.com/login", Notes: "synthetic notes",
			ImportSource: []byte(`{"source":"synthetic-export"}`),
			Passkeys:     [][]byte{fixturePasskeyRecord(t)},
			History: []vault.ItemHistoryEntry{{
				Timestamp: 1_700_000_000, Action: "password-change",
				Password: "synthetic-old-password",
			}},
			Attachments: []vault.AttachmentMeta{{
				ID: "recovery", FileName: "recovery.txt", Size: int64(len(attContent)),
				SHA256: vault.AttachmentSHA256(attContent), Content: attContent,
			}},
			CreatedAt: 1, UpdatedAt: 2,
		},
		{
			ID: "document-1", Kind: "document", Title: "Binary document",
			Filename: "fixture.bin", Attachment: []byte("synthetic legacy document body"), AttachmentProtected: true,
		},
	}
	db, err := vault.NewItemDatabase([]byte(`{"fixture":"synthetic-metadata"}`), items)
	if err != nil {
		t.Fatalf("NewItemDatabase: %v", err)
	}
	return db
}

// sealRemote produces the exact remote bytes through the public
// SealAuthenticatedFile and OpenAuthenticatedFile paths and checks the public
// open accepts them under the caller pin.
func sealRemote(t *testing.T) []byte {
	t.Helper()
	p, id, signingKey := fixtureInputs(t)
	cp := fixturePin(t, p)
	encoded, err := vaultfile.SealAuthenticatedFile(fixtureDraft(t, p), itemDatabase(t), cp, makeVUK(t), signingKey)
	if err != nil {
		t.Fatalf("SealAuthenticatedFile: %v", err)
	}
	_, opened, err := vaultfile.OpenAuthenticatedFile(encoded, cp, fixtureDeviceID, id)
	if err != nil {
		t.Fatalf("fixture does not open under the caller pin: %v", err)
	}
	releaseDatabase(opened)
	if bytes.Contains(encoded, []byte("synthetic-password")) {
		t.Fatal("fixture ciphertext contains a plaintext marker")
	}
	return encoded
}

func makeVUK(t *testing.T) []byte {
	t.Helper()
	vuk := make([]byte, vaultfile.CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal(err)
	}
	return vuk
}

// dirBackend adapts a real directory backend and records each Read result.
type dirBackend struct {
	*vaultfilebackend.Dir
	mu     sync.Mutex
	reads  int
	last   vaultfilebackend.ReadResult
	cancel context.CancelFunc
}

func (d *dirBackend) Read(ctx context.Context, name string) (vaultfilebackend.ReadResult, error) {
	res, err := d.Dir.Read(ctx, name)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reads++
	if err == nil {
		d.last = vaultfilebackend.ReadResult{Bytes: bytes.Clone(res.Bytes), Revision: res.Revision}
	}
	if d.cancel != nil {
		d.cancel()
	}
	return res, err
}

func (d *dirBackend) readCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reads
}

func (d *dirBackend) lastRead() vaultfilebackend.ReadResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last
}

// fixture is one written remote file served from a real temporary directory
// backend and the caller's credentials.
type fixture struct {
	remote *dirBackend
	pin    *vaultfile.PolicyCheckpoint
	id     *age.X25519Identity
	bytes  []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	p, id, _ := fixtureInputs(t)
	remoteBytes := sealRemote(t)
	store := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	backend, err := vaultfilebackend.OpenDir(store)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	d := &dirBackend{Dir: backend}
	if err := d.CreateIfAbsent(context.Background(), remoteName, remoteBytes); err != nil {
		t.Fatalf("CreateIfAbsent: %v", err)
	}
	return &fixture{remote: d, pin: fixturePin(t, p), id: id, bytes: remoteBytes}
}

// openJournal opens a fresh private bbolt journal in its own directory.
func (f *fixture) openJournal(t *testing.T) *vaultfilejournal.Journal {
	t.Helper()
	return openNewJournal(t)
}

// openNewJournal opens an empty journal database in a fresh private directory
// below the test's temp root, exactly the shape vaultfilejournal.Open checks.
// Every call gets a new database path and its close is registered.
func openNewJournal(t *testing.T) *vaultfilejournal.Journal {
	t.Helper()
	return openJournalAt(t, journalDBPath(t))
}

func (f *fixture) bootstrap(t *testing.T, ctx context.Context, j *vaultfilejournal.Journal) (Receipt, error) {
	t.Helper()
	return Bootstrap(ctx, f.remote, j, remoteName, f.pin, fixtureDeviceID, f.id)
}

func wantEmptyJournal(t *testing.T, j *vaultfilejournal.Journal) {
	t.Helper()
	if _, err := j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("proposal record = %v, want ErrEmpty", err)
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("prepared record = %v, want ErrEmpty", err)
	}
	if _, err := j.LoadState(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("state record = %v, want ErrEmpty", err)
	}
}

func wantZeroReceipt(t *testing.T, r Receipt) {
	t.Helper()
	if r != (Receipt{}) {
		t.Fatalf("error path returned a non-zero receipt: %+v", r)
	}
}

func wantNoPlaintext(t *testing.T, err error, r Receipt) {
	t.Helper()
	s := string(r.RemoteRevision) + "\x00" + r.FileDigest
	if err != nil {
		s += "\x00" + err.Error()
	}
	for _, marker := range plaintextMarkers {
		if strings.Contains(s, marker) {
			t.Fatalf("receipt or error leaked plaintext %q", marker)
		}
	}
}

func TestBootstrapPositive(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	r, err := f.bootstrap(t, context.Background(), j)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	parsed, err := vaultfile.ParseFile(f.bytes)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := vaultfile.FileDigest(parsed)
	if err != nil {
		t.Fatal(err)
	}
	read := f.remote.lastRead()
	if f.remote.readCount() != 1 {
		t.Fatalf("backend reads = %d, want exactly 1", f.remote.readCount())
	}
	if r.RemoteRevision != read.Revision {
		t.Fatalf("receipt revision = %q, want the opaque revision %q read", r.RemoteRevision, read.Revision)
	}
	if r.FileDigest != wantDigest {
		t.Fatalf("receipt digest = %q, want %q", r.FileDigest, wantDigest)
	}
	if r.Generation != 0 {
		t.Fatalf("receipt generation = %d, want 0", r.Generation)
	}

	state, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !bytes.Equal(state.BaseBytes, f.bytes) || !bytes.Equal(state.WorkingBytes, f.bytes) {
		t.Fatal("journal bytes are not the exact remote bytes")
	}
	if state.RemoteRevision != read.Revision || state.Generation != 0 {
		t.Fatalf("journal = rev %q gen %d, want rev %q gen 0", state.RemoteRevision, state.Generation, read.Revision)
	}
	if _, err := j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("proposal record = %v, want ErrEmpty", err)
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("prepared record = %v, want ErrEmpty", err)
	}

	// Close the writable journal before reopening the same path; compare the
	// exact record, then confirm that a repeated Bootstrap is refused as a
	// non-empty journal instead of succeeding idempotently.
	path := journalPath(t, j)
	closeNow(t, j)
	reopened := openJournalAt(t, path)
	got, err := reopened.LoadState()
	if err != nil {
		t.Fatalf("reloaded LoadState: %v", err)
	}
	if !bytes.Equal(got.BaseBytes, f.bytes) || !bytes.Equal(got.WorkingBytes, f.bytes) ||
		got.RemoteRevision != read.Revision || got.Generation != 0 {
		t.Fatal("reopened journal does not hold the exact bootstrap state")
	}
	r2, err := f.bootstrap(t, context.Background(), reopened)
	if !errors.Is(err, ErrJournal) || !errors.Is(err, vaultfilejournal.ErrJournalNotEmpty) ||
		!errors.Is(err, vaultfilejournal.ErrStateExists) {
		t.Fatalf("repeated Bootstrap = %v, want ErrJournal wrapping ErrJournalNotEmpty and ErrStateExists", err)
	}
	wantZeroReceipt(t, r2)
	wantNoPlaintext(t, err, r2)
	// The caller confirms the committed state itself.
	after, err := reopened.LoadState()
	if err != nil {
		t.Fatalf("LoadState after refused repeat: %v", err)
	}
	if !bytes.Equal(after.BaseBytes, f.bytes) || !bytes.Equal(after.WorkingBytes, f.bytes) ||
		after.RemoteRevision != read.Revision || after.Generation != 0 {
		t.Fatal("a refused repeat changed the committed bootstrap state")
	}
	if f.remote.readCount() != 2 {
		t.Fatalf("backend reads = %d, want 2 (initial and refused repeat)", f.remote.readCount())
	}
	wantNoPlaintext(t, nil, r)
}

func TestBootstrapWrongPinWritesNothing(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	wrong := *f.pin
	wrong.PolicyDigest = bytes.Repeat([]byte{0x5a}, 32)
	r, err := Bootstrap(context.Background(), f.remote, j, remoteName, &wrong, fixtureDeviceID, f.id)
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("Bootstrap with a wrong pin = %v, want ErrVerify", err)
	}
	if code := vaultfileCode(err); code != vaultfile.CodePolicyCheckpointFailed {
		t.Fatalf("wrong pin failed with %q, want %q", code, vaultfile.CodePolicyCheckpointFailed)
	}
	wantZeroReceipt(t, r)
	wantNoPlaintext(t, err, r)
	wantEmptyJournal(t, j)
}

func TestBootstrapWrongIdentityWritesNothing(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	foreign, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Bootstrap(context.Background(), f.remote, j, remoteName, f.pin, fixtureDeviceID, foreign)
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("Bootstrap with a foreign identity = %v, want ErrVerify", err)
	}
	wantZeroReceipt(t, r)
	wantNoPlaintext(t, err, r)
	wantEmptyJournal(t, j)
}

// TestBootstrapNonItemDatabaseWritesNothing authenticates a valid file whose
// KDBX is not the item-database layout: the structure check must reject it
// before any journal write.
func TestBootstrapNonItemDatabaseWritesNothing(t *testing.T) {
	f := newFixture(t)
	p, _, signingKey := fixtureInputs(t)
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	group := kdbx.NewGroup()
	group.Name = "Not the item layout"
	group.Entries = []kdbx.Entry{kdbx.NewEntry()}
	db.Content.Root.Groups = []kdbx.Group{group}
	nonItem, err := vaultfile.SealAuthenticatedFile(fixtureDraft(t, p), db, f.pin, makeVUK(t), signingKey)
	if err != nil {
		t.Fatalf("SealAuthenticatedFile: %v", err)
	}
	// Read the current revision of the bytes CreateIfAbsent committed,
	// without going through the recording adapter.
	cur, err := f.remote.Dir.Read(context.Background(), remoteName)
	if err != nil {
		t.Fatalf("Read current revision: %v", err)
	}
	if err := f.remote.ReplaceIfVersion(context.Background(), remoteName, cur.Revision, nonItem); err != nil {
		t.Fatalf("ReplaceIfVersion: %v", err)
	}
	j := f.openJournal(t)
	r, err := f.bootstrap(t, context.Background(), j)
	if !errors.Is(err, ErrVerify) || !errors.Is(err, vault.ErrSnapshot) {
		t.Fatalf("Bootstrap = %v, want ErrVerify wrapping vault.ErrSnapshot", err)
	}
	wantZeroReceipt(t, r)
	wantEmptyJournal(t, j)
}

func TestBootstrapCancellation(t *testing.T) {
	t.Run("before call", func(t *testing.T) {
		f := newFixture(t)
		j := f.openJournal(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r, err := f.bootstrap(t, ctx, j)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Bootstrap = %v, want context.Canceled", err)
		}
		wantZeroReceipt(t, r)
		if f.remote.readCount() != 0 {
			t.Fatal("a cancelled call read the backend")
		}
		wantEmptyJournal(t, j)
	})
	t.Run("immediately after read", func(t *testing.T) {
		f := newFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.remote.cancel = cancel
		j := f.openJournal(t)
		r, err := f.bootstrap(t, ctx, j)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Bootstrap = %v, want context.Canceled", err)
		}
		if !errors.Is(err, vaultfilebackend.ErrDenied) {
			t.Logf("cancel observed as %v", err)
		}
		wantZeroReceipt(t, r)
		wantNoPlaintext(t, err, r)
		if f.remote.readCount() != 1 {
			t.Fatalf("backend reads = %d, want 1", f.remote.readCount())
		}
		wantEmptyJournal(t, j)
	})
}

// journalPaths records the path each open journal was created at, so a test can
// close it and reopen the same file. Entries are added by openJournalAt and
// removed by closeNow.
var (
	journalPathsMu sync.Mutex
	journalPaths   = map[*vaultfilejournal.Journal]string{}
)

// openJournalAt opens the journal at path, records its path and registers with
// t.Cleanup a close of it if the test did not close it already. Registration is
// per call, never a process-wide leftover, so no entry or file lock outlives its
// test.
func openJournalAt(t *testing.T, path string) *vaultfilejournal.Journal {
	t.Helper()
	j, err := vaultfilejournal.Open(path)
	if err != nil {
		t.Fatalf("journal Open: %v", err)
	}
	journalPathsMu.Lock()
	journalPaths[j] = path
	journalPathsMu.Unlock()
	t.Cleanup(func() {
		journalPathsMu.Lock()
		_, open := journalPaths[j]
		delete(journalPaths, j)
		journalPathsMu.Unlock()
		if open {
			if err := j.Close(); err != nil {
				t.Errorf("journal Close at cleanup: %v", err)
			}
		}
	})
	return j
}

// journalPath returns the path j was opened at.
func journalPath(t *testing.T, j *vaultfilejournal.Journal) string {
	t.Helper()
	journalPathsMu.Lock()
	defer journalPathsMu.Unlock()
	path, ok := journalPaths[j]
	if !ok {
		t.Fatal("journal path not recorded")
	}
	return path
}

// closeNow closes j immediately, before any other bbolt open of the same file:
// bbolt holds an exclusive file lock for the lifetime of the handle, so a
// second open (even a read-only one) of an open database blocks or fails.
func closeNow(t *testing.T, j *vaultfilejournal.Journal) {
	t.Helper()
	journalPathsMu.Lock()
	delete(journalPaths, j)
	journalPathsMu.Unlock()
	if err := j.Close(); err != nil {
		t.Fatalf("journal Close: %v", err)
	}
}

// rawBolt opens the journal database directly for fixtures the public API
// cannot produce. The journal must not be open at the same time.
func rawBolt(t *testing.T, path string, fn func(tx *bolt.Tx) error) {
	t.Helper()
	if err := openRaw(t, path, fn); err != nil {
		t.Fatalf("raw bolt: %v", err)
	}
}

// openRaw runs fn in one write transaction on the bare database at path.
func openRaw(t *testing.T, path string, fn func(tx *bolt.Tx) error) error {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(fn)
}

// dumpRecords copies every raw key of every bucket, nested buckets included.
func dumpRecords(t *testing.T, path string) map[string]map[string][]byte {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("dump open: %v", err)
	}
	defer db.Close()
	out := map[string]map[string][]byte{}
	err = db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			return dumpBucket(string(name), b, out)
		})
	})
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	return out
}

// dumpBucket copies the entries of b into out under the keys "<prefix>\x00<key>",
// recursing into nested buckets so a record key that holds one is compared by
// shape as well as by content.
func dumpBucket(prefix string, b *bolt.Bucket, out map[string]map[string][]byte) error {
	entries := map[string][]byte{}
	out[prefix] = entries
	return b.ForEach(func(k, v []byte) error {
		key := prefix + "\x00" + string(k)
		if nb := b.Bucket(k); nb != nil {
			return dumpBucket(key, nb, out)
		}
		entries[key] = bytes.Clone(v)
		return nil
	})
}

func sameRecords(a, b map[string]map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for name, entries := range a {
		other, ok := b[name]
		if !ok || len(entries) != len(other) {
			return false
		}
		for k, v := range entries {
			if !bytes.Equal(other[k], v) {
				return false
			}
		}
	}
	return true
}

// TestBootstrapPreservesExistingRecords preloads each kind of durable record,
// then runs Bootstrap against a remote with newer content and checks that it is
// refused and every stored record is preserved exactly.
func TestBootstrapPreservesExistingRecords(t *testing.T) {
	oldBase := []byte("synthetic-old-base")
	cases := []struct {
		name  string
		setup func(t *testing.T, path string)
		want  error
		// apiState is set when the case preloaded its state through the
		// public API, so the state must still be the exact preloaded one.
		apiState *vaultfilejournal.State
	}{
		{
			name: "existing working edit",
			setup: func(t *testing.T, path string) {
				j := openJournalAt(t, path)
				if err := j.InitializeState(vaultfilejournal.State{BaseBytes: oldBase, RemoteRevision: "old-rev", WorkingBytes: []byte("synthetic-local-edit")}); err != nil {
					t.Fatal(err)
				}
				if err := j.UpdateWorking(0, []byte("synthetic-local-edit-2")); err != nil {
					t.Fatal(err)
				}
				closeNow(t, j)
			},
			want:     vaultfilejournal.ErrJournalNotEmpty,
			apiState: &vaultfilejournal.State{BaseBytes: oldBase, RemoteRevision: "old-rev", WorkingBytes: []byte("synthetic-local-edit-2"), Generation: 1},
		},
		{
			name: "legacy proposal",
			setup: func(t *testing.T, path string) {
				j := openJournalAt(t, path)
				if err := j.InitializeState(vaultfilejournal.State{BaseBytes: oldBase, RemoteRevision: "old-rev", WorkingBytes: []byte("synthetic-old-working")}); err != nil {
					t.Fatal(err)
				}
				if err := j.Save(vaultfilejournal.Proposal{Generation: 3, OperationID: "op-legacy", ExpectedRevision: "old-rev", Bytes: []byte("synthetic-sealed-proposal")}); err != nil {
					t.Fatal(err)
				}
				closeNow(t, j)
			},
			want:     vaultfilejournal.ErrJournalNotEmpty,
			apiState: &vaultfilejournal.State{BaseBytes: oldBase, RemoteRevision: "old-rev", WorkingBytes: []byte("synthetic-old-working")},
		},
		{
			name: "prepared proposal",
			setup: func(t *testing.T, path string) {
				j := openJournalAt(t, path)
				if err := j.InitializeState(vaultfilejournal.State{BaseBytes: oldBase, RemoteRevision: "old-rev", WorkingBytes: []byte("synthetic-sealed-proposal")}); err != nil {
					t.Fatal(err)
				}
				if err := j.Prepare(0, vaultfilejournal.Proposal{Generation: 1, OperationID: "op-prepared", ExpectedRevision: "old-rev", Bytes: []byte("synthetic-sealed-proposal")}); err != nil {
					t.Fatal(err)
				}
				closeNow(t, j)
			},
			want:     vaultfilejournal.ErrJournalNotEmpty,
			apiState: &vaultfilejournal.State{BaseBytes: oldBase, RemoteRevision: "old-rev", WorkingBytes: []byte("synthetic-sealed-proposal")},
		},
		// An existing state is refused as non-empty whatever its bytes; the
		// empty-only initializer never decodes it.
		{
			name: "corrupt state record",
			setup: func(t *testing.T, path string) {
				rawBolt(t, path, func(tx *bolt.Tx) error {
					b, err := tx.CreateBucketIfNotExists([]byte("journal"))
					if err != nil {
						return err
					}
					return b.Put([]byte("state"), []byte("synthetic-corrupt-record"))
				})
			},
			want: vaultfilejournal.ErrJournalNotEmpty,
		},
		// A known record key that holds a nested bucket has no value at all
		// in bbolt; it must be ErrCorrupt, never treated as absent.
		{
			name: "state key is a nested bucket",
			setup: func(t *testing.T, path string) {
				rawBolt(t, path, func(tx *bolt.Tx) error {
					b, err := tx.CreateBucketIfNotExists([]byte("journal"))
					if err != nil {
						return err
					}
					nb, err := b.CreateBucket([]byte("state"))
					if err != nil {
						return err
					}
					return nb.Put([]byte("nested"), []byte("synthetic-nested"))
				})
			},
			want: vaultfilejournal.ErrCorrupt,
		},
		{
			name: "unknown record",
			setup: func(t *testing.T, path string) {
				rawBolt(t, path, func(tx *bolt.Tx) error {
					b, err := tx.CreateBucketIfNotExists([]byte("journal"))
					if err != nil {
						return err
					}
					return b.Put([]byte("future-record"), []byte("synthetic-unknown"))
				})
			},
			want: vaultfilejournal.ErrJournalNotEmpty,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			path := journalDBPath(t)
			tc.setup(t, path)
			// Snapshot every record from a separate read-only open, because
			// bbolt rewrites the file's meta pages whenever it is opened. No
			// journal may be open at path while dumpRecords opens it.
			before := dumpRecords(t, path)
			j := openJournalAt(t, path)
			r, err := f.bootstrap(t, context.Background(), j)
			if !errors.Is(err, ErrJournal) || !errors.Is(err, tc.want) {
				t.Fatalf("Bootstrap = %v, want ErrJournal wrapping %v", err, tc.want)
			}
			if errors.Is(err, vaultfilejournal.ErrCorrupt) != (tc.want == vaultfilejournal.ErrCorrupt) {
				t.Fatalf("Bootstrap = %v, ErrCorrupt classification mismatch for %v", err, tc.want)
			}
			wantZeroReceipt(t, r)
			// The writable journal must be closed before any second open of
			// the same file: the read-only dump below cannot share it.
			closeNow(t, j)
			// Compare every stored record with the pre-call snapshot. The
			// rejected call's transaction was rolled back completely.
			after := dumpRecords(t, path)
			if !sameRecords(before, after) {
				t.Fatal("a rejected Bootstrap changed the stored records")
			}
			// Reopen, now that the dump is closed, and read the state.
			re := openJournalAt(t, path)
			state, stateErr := re.LoadState()
			if stateErr == nil && bytes.Equal(state.BaseBytes, f.bytes) {
				t.Fatal("a rejected Bootstrap stored the remote bytes")
			}
			// The cases the public API preloaded keep their state.
			if tc.apiState != nil {
				if stateErr != nil || !bytes.Equal(state.BaseBytes, tc.apiState.BaseBytes) ||
					state.RemoteRevision != tc.apiState.RemoteRevision || !bytes.Equal(state.WorkingBytes, tc.apiState.WorkingBytes) ||
					state.Generation != tc.apiState.Generation {
					t.Fatalf("the preloaded local state was lost: %+v %v", state, stateErr)
				}
			}
		})
	}
}

// vaultfileCode returns the *vaultfile.Error code in err, or "".
func vaultfileCode(err error) string {
	var e *vaultfile.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// journalDBPath returns an unused database path below a fresh private
// directory.
func journalDBPath(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "journal.db")
}
