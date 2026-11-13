package vaultfilejournal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

func openAt(t *testing.T, dir string) *Journal {
	t.Helper()
	j, err := Open(filepath.Join(dir, "journal.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}

func mustSave(t *testing.T, j *Journal, p Proposal) {
	t.Helper()
	if err := j.Save(p); err != nil {
		t.Fatalf("Save(gen %d): %v", p.Generation, err)
	}
}

func mustLoad(t *testing.T, j *Journal) Proposal {
	t.Helper()
	p, err := j.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return p
}

func assertProposal(t *testing.T, got, want Proposal) {
	t.Helper()
	if got.Generation != want.Generation ||
		got.OperationID != want.OperationID ||
		got.ExpectedRevision != want.ExpectedRevision ||
		!bytes.Equal(got.Bytes, want.Bytes) {
		t.Fatalf("proposal mismatch:\n got gen=%d op=%q rev=%q bytes=%d\nwant gen=%d op=%q rev=%q bytes=%d",
			got.Generation, got.OperationID, got.ExpectedRevision, len(got.Bytes),
			want.Generation, want.OperationID, want.ExpectedRevision, len(want.Bytes))
	}
}

// opaque returns deterministic pseudo-random, non-textual bytes that mimic a
// sealed (encrypted) proposal.
func opaque(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31+int(seed)*7) ^ 0xa5
	}
	return b
}

func baseProposal() Proposal {
	return Proposal{
		Generation:       7,
		OperationID:      "op-2026-11-11:test_run.1",
		ExpectedRevision: vaultfilebackend.Revision(`"9c1f-etag"`),
		Bytes:            opaque(1<<10+17, 3),
	}
}

// TestConcurrentUse is a race-detector sanity check for the mutex.
func TestConcurrentUse(t *testing.T) {
	j := openAt(t, privateDir(t))
	mustSave(t, j, baseProposal())
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for k := 0; k < 20; k++ {
				_ = j.Save(baseProposal())
				_, _ = j.Load()
			}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

// TestSaveLoadAcrossReopen is the real-file smoke test: a new journal stores
// an opaque proposal durably, and a reopened journal hands back the exact
// generation, operation ID, expected revision and bytes.
func TestSaveLoadAcrossReopen(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "journal.db")
	want := baseProposal()

	j, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := j.Load(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("fresh Load = %v, want ErrEmpty", err)
	}
	mustSave(t, j, want)
	if err := j.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := j.Load(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Load after Close = %v, want ErrClosed", err)
	}

	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("database is not a regular file: %v", fi.Mode())
	}
	// Mode bits are only meaningful on POSIX; Windows private DACLs are
	// covered by the dedicated ACL tests.
	checkLocalPermissions(t, path, dir)

	j2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer j2.Close()
	got := mustLoad(t, j2)
	assertProposal(t, got, want)

	// Load returns a copy: mutating it must not affect the stored record.
	got.Bytes[0] ^= 0xff
	assertProposal(t, mustLoad(t, j2), want)

	// Save must not retain the caller's bytes either.
	want = baseProposal()
	p := baseProposal()
	p.Generation = 8
	p.Bytes = opaque(64, 9)
	mustSave(t, j2, p)
	p.Bytes[0] ^= 0xff
	stored := mustLoad(t, j2)
	want = Proposal{Generation: 8, OperationID: p.OperationID, ExpectedRevision: p.ExpectedRevision, Bytes: opaque(64, 9)}
	assertProposal(t, stored, want)
}

// TestMaxSizeProposalRoundTrip stores a full-size opaque proposal and a
// maximum-length revision.
func TestMaxSizeProposalRoundTrip(t *testing.T) {
	dir := privateDir(t)
	want := Proposal{
		Generation:       ^uint64(0),
		OperationID:      strings.Repeat("a", MaxOperationIDBytes),
		ExpectedRevision: vaultfilebackend.Revision(strings.Repeat("r", MaxExpectedRevisionBytes)),
		Bytes:            opaque(MaxProposalBytes, 1),
	}
	j := openAt(t, dir)
	mustSave(t, j, want)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	assertProposal(t, mustLoad(t, openAt(t, dir)), want)
}

// TestOpenRejectsInvalidPaths covers the private-file placement rules.
func TestOpenRejectsInvalidPaths(t *testing.T) {
	t.Run("relative", func(t *testing.T) {
		if _, err := Open("journal.db"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		if _, err := Open(""); !errors.Is(err, ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})
	t.Run("missing_parent", func(t *testing.T) {
		if _, err := Open(filepath.Join(privateDir(t), "nope", "journal.db")); !errors.Is(err, ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})
	t.Run("shared_parent", func(t *testing.T) {
		dir := privateDir(t)
		makeParentShared(t, dir)
		if _, err := Open(filepath.Join(dir, "journal.db")); !errors.Is(err, ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "journal.db")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected Open left a database file: %v", err)
		}
	})
	t.Run("symlinked_parent", func(t *testing.T) {
		real := privateDir(t)
		link := filepath.Join(privateDir(t), "link")
		mustLinkDir(t, real, link)
		if _, err := Open(filepath.Join(link, "journal.db")); !errors.Is(err, ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
		if _, err := os.Lstat(filepath.Join(real, "journal.db")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Open through a link created a database: %v", err)
		}
	})
	t.Run("symlinked_db", func(t *testing.T) {
		dir := privateDir(t)
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		mustLinkFile(t, target, filepath.Join(dir, "journal.db"))
		if _, err := Open(filepath.Join(dir, "journal.db")); !errors.Is(err, ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
		if info, err := os.Lstat(target); err != nil || info.Size() != 0 {
			t.Fatalf("Open through a file link changed the target: %v, %v", info, err)
		}
	})
	t.Run("directory_db", func(t *testing.T) {
		dir := privateDir(t)
		if err := os.Mkdir(filepath.Join(dir, "journal.db"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(filepath.Join(dir, "journal.db")); !errors.Is(err, ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})
	t.Run("non_bolt_file_preserved", func(t *testing.T) {
		dir := privateDir(t)
		path := filepath.Join(dir, "journal.db")
		if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
			t.Fatal(err)
		}
		makeDBPrivate(t, path)
		if _, err := Open(path); err == nil {
			t.Fatal("Open accepted a non-bbolt file")
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "not a database" {
			t.Fatalf("failed Open modified the existing file: %q, %v", data, err)
		}
	})
	t.Run("existing_db_group_readable_posix", func(t *testing.T) {
		if !posixModeChecks {
			t.Skip("POSIX mode bits are not ACL evidence on Windows; DACL checks are tested separately")
		}
		dir := privateDir(t)
		path := filepath.Join(dir, "journal.db")
		j, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		before := mustReadFile(t, path)
		if _, err := Open(path); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Open(group-readable db) = %v, want ErrInvalid", err)
		}
		if got := mustReadFile(t, path); !bytes.Equal(got, before) {
			t.Fatal("rejecting a group-readable database changed its bytes")
		}
		if fi, err := os.Lstat(path); err != nil || fi.Mode().Perm() != 0o640 {
			t.Fatalf("rejecting a group-readable database chmodded it: %v, %v", fi, err)
		}
	})
}

// TestSaveRejectsInvalidProposals checks every field bound without writing.
func TestSaveRejectsInvalidProposals(t *testing.T) {
	j := openAt(t, privateDir(t))
	mustSave(t, j, baseProposal())
	good := func() Proposal {
		p := baseProposal()
		p.Generation = 8
		return p
	}
	cases := map[string]func(*Proposal){
		"zero-generation":     func(p *Proposal) { p.Generation = 0 },
		"empty-operation":     func(p *Proposal) { p.OperationID = "" },
		"operation-too-long":  func(p *Proposal) { p.OperationID = strings.Repeat("a", MaxOperationIDBytes+1) },
		"operation-uppercase": func(p *Proposal) { p.OperationID = "Op" },
		"operation-space":     func(p *Proposal) { p.OperationID = "op 1" },
		"operation-newline":   func(p *Proposal) { p.OperationID = "op\n" },
		"operation-nul":       func(p *Proposal) { p.OperationID = "op\x00" },
		"operation-slash":     func(p *Proposal) { p.OperationID = "op/1" },
		"operation-non-ascii": func(p *Proposal) { p.OperationID = "opé" },
		"revision-too-long": func(p *Proposal) {
			p.ExpectedRevision = vaultfilebackend.Revision(strings.Repeat("r", MaxExpectedRevisionBytes+1))
		},
		"empty-bytes":     func(p *Proposal) { p.Bytes = nil },
		"bytes-too-large": func(p *Proposal) { p.Bytes = make([]byte, MaxProposalBytes+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := good()
			mutate(&p)
			if err := j.Save(p); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Save = %v, want ErrInvalid", err)
			}
		})
	}
	// None of the rejected proposals replaced the stored record.
	assertProposal(t, mustLoad(t, j), baseProposal())

	// Boundaries are inclusive: a maximum-length operation ID and an empty
	// (create) revision are valid.
	p := good()
	p.OperationID = strings.Repeat("z", MaxOperationIDBytes)
	p.ExpectedRevision = ""
	mustSave(t, j, p)
	assertProposal(t, mustLoad(t, j), p)
}

// TestSameGenerationReplayIdempotent proves an exact replay replaces nothing,
// even when the caller passes a fresh slice.
func TestSameGenerationReplayIdempotent(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	want := baseProposal()
	mustSave(t, j, want)
	before := mustLoad(t, j)

	replay := want
	replay.Bytes = bytes.Clone(want.Bytes)
	if err := j.Save(replay); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	assertProposal(t, mustLoad(t, j), want)

	// A same-generation proposal that differs in any single field is rejected
	// and leaves the record unchanged.
	variants := map[string]func(*Proposal){
		"bytes":       func(p *Proposal) { p.Bytes = append(bytes.Clone(p.Bytes), 0) },
		"bytes-value": func(p *Proposal) { p.Bytes = bytes.Clone(p.Bytes); p.Bytes[0] ^= 1 },
		"operation":   func(p *Proposal) { p.OperationID = "other-op" },
		"revision":    func(p *Proposal) { p.ExpectedRevision = `W/"9c1f-etag"` },
	}
	for name, mutate := range variants {
		t.Run("conflict-"+name, func(t *testing.T) {
			p := want
			p.Bytes = bytes.Clone(want.Bytes)
			mutate(&p)
			err := j.Save(p)
			var conflict *SavedGenerationConflictError
			if !errors.As(err, &conflict) || !errors.Is(err, ErrInvalid) {
				t.Fatalf("Save = %v, want *SavedGenerationConflictError matching ErrInvalid", err)
			}
			if conflict.Generation != want.Generation || conflict.OperationID != want.OperationID {
				t.Fatalf("conflict reports %+v", conflict)
			}
			assertProposal(t, mustLoad(t, j), want)
		})
	}

	// The no-op and rejected saves persist nothing: after reopen the record is
	// bit-for-bit the original.
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j2, err := Open(filepath.Join(dir, "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer j2.Close()
	assertProposal(t, mustLoad(t, j2), before)
}

// TestStaleGenerationRejected proves a lower generation never replaces newer
// state.
func TestStaleGenerationRejected(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	newer := baseProposal()
	mustSave(t, j, newer)
	before := mustReadFile(t, filepath.Join(dir, "journal.db"))

	for _, gen := range []uint64{1, newer.Generation - 1} {
		p := baseProposal()
		p.Generation = gen
		p.OperationID = "older-op"
		if err := j.Save(p); !errors.Is(err, ErrStaleGeneration) {
			t.Fatalf("Save(gen %d) = %v, want ErrStaleGeneration", gen, err)
		}
		assertProposal(t, mustLoad(t, j), newer)
	}
	if after := mustReadFile(t, filepath.Join(dir, "journal.db")); !bytes.Equal(before, after) {
		t.Fatal("a rejected stale save rewrote the database file")
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
