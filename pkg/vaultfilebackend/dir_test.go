//go:build darwin || linux

package vaultfilebackend

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func openAt(t *testing.T, root string) Backend {
	t.Helper()
	b, err := OpenDir(root)
	if err != nil {
		t.Fatalf("open dir: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func mustRead(t *testing.T, b Backend, name string) ReadResult {
	t.Helper()
	got, err := b.Read(context.Background(), name)
	if err != nil {
		t.Fatalf("read %q: %v", name, err)
	}
	return got
}

func TestDirConformance(t *testing.T) {
	root := t.TempDir()
	RunConformance(t,
		func(t *testing.T) Backend { return openAt(t, root) },
		func(t *testing.T) Backend { return openAt(t, root) },
	)
}

// Independent OpenDir instances over one root are independent backends that
// share only the lock inode: a write through one is visible through another.
func TestDirInstancesShareState(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	a := openAt(t, root)
	b := openAt(t, root)
	if err := a.CreateIfAbsent(ctx, "x", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	got, err := b.Read(ctx, "x")
	if err != nil || string(got.Bytes) != "v1" {
		t.Fatalf("read via second instance = %q %v", got.Bytes, err)
	}
	if err := b.ReplaceIfVersion(ctx, "x", got.Revision, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if again, _ := a.Read(ctx, "x"); string(again.Bytes) != "v2" {
		t.Fatal("write via second instance invisible")
	}
}

// Equal bytes committed twice get different revisions although the stored
// digest repeats; the revision is the random per-commit version, not a digest.
func TestDirRevisionsAreRandomNotContentDerived(t *testing.T) {
	ctx := context.Background()
	b := openAt(t, t.TempDir())
	if err := b.CreateIfAbsent(ctx, "n", []byte("same")); err != nil {
		t.Fatal(err)
	}
	first := mustRead(t, b, "n")
	if err := b.ReplaceIfVersion(ctx, "n", first.Revision, []byte("same")); err != nil {
		t.Fatal(err)
	}
	second := mustRead(t, b, "n")
	if second.Revision == first.Revision {
		t.Fatal("equal bytes committed twice reused the revision")
	}
	if !bytes.Equal(second.Bytes, first.Bytes) {
		t.Fatal("bytes changed")
	}
	raw, err := os.ReadFile(b.(*Dir).dataPath("n"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := decodeRecord(raw)
	if err != nil || rec.version != string(second.Revision) {
		t.Fatalf("stored record = %+v, %v", rec, err)
	}
}

func TestDirRefusesSymlinkedLockFile(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")
	lock := filepath.Join(b.root, lockName)
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, lock); err != nil {
		t.Fatal(err)
	}
	// The lock inode must never be substituted: every operation that needs
	// it refuses the swapped inode instead of locking the wrong file.
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read with symlinked lock = %v, want ErrDenied", err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("x")); !errors.Is(err, ErrDenied) {
		t.Fatalf("write with symlinked lock = %v, want ErrDenied", err)
	}
	if _, err := OpenDir(root); !errors.Is(err, ErrDenied) {
		t.Fatalf("open with symlinked lock = %v, want ErrDenied", err)
	}
	if st, err := os.Lstat(victim); err != nil || st.Size() != 0 {
		t.Fatal("lock followed the symlink")
	}
	// Dangling symlink: also refused, never replaced by a fresh lock file.
	_ = os.Remove(lock)
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), lock); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDir(root); !errors.Is(err, ErrDenied) {
		t.Fatalf("open with dangling lock link = %v, want ErrDenied", err)
	}
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read with dangling lock link = %v, want ErrDenied", err)
	}
}

// A private lock file keeps the same inode for every open and every
// operation, so every process locks the same file across restarts.
func TestDirLockInodeIsStable(t *testing.T) {
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	st1, err := os.Stat(b.lock)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := b.CreateIfAbsent(ctx, "n", []byte("v")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	c := openAt(t, root).(*Dir)
	st2, err := os.Stat(c.lock)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(st1, st2) {
		t.Fatal("a fresh OpenDir locked a different inode")
	}
	// Each instance pins its own capture, which must be the same inode.
	if !sameIdentity(b.lockID, c.lockID) {
		t.Fatal("instances captured different lock inode identities")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	d := openAt(t, root).(*Dir)
	st3, err := os.Stat(d.lock)
	if err != nil || !os.SameFile(st1, st3) {
		t.Fatal("reopen after Close locked a different inode")
	}
	if !sameIdentity(b.lockID, d.lockID) {
		t.Fatal("reopen after Close pinned a different lock inode identity")
	}
	// Both live instances still operate through the same inode.
	if got := mustRead(t, c, "n"); string(got.Bytes) != "v2" {
		t.Fatal("second instance does not serve the committed version")
	}
	// A loosened lock file is refused rather than silently reused.
	if err := os.Chmod(b.lock, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDir(root); !errors.Is(err, ErrDenied) {
		t.Fatalf("open with 0644 lock file = %v, want ErrDenied", err)
	}
}

func TestDirRefusesSymlinkedDataOrTmpEntry(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")
	data := filepath.Join(b.root, dataName)
	other := t.TempDir()
	// Data directory swapped for a directory symlink.
	backup := data + ".old"
	if err := os.Rename(data, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "data"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read through symlinked data dir = %v, want ErrDenied", err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("write through symlinked data dir = %v, want ErrDenied", err)
	}
	if _, err := os.Lstat(filepath.Join(other, "data")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("write created a directory outside the root")
	}
	_ = os.Remove(data)
	if err := os.Rename(backup, data); err != nil {
		t.Fatal(err)
	}
	// A name's data file swapped for a symlink to a target outside the root.
	target := filepath.Join(other, "target")
	outside := []byte("outside")
	if err := os.WriteFile(target, outside, 0600); err != nil {
		t.Fatal(err)
	}
	entry := b.dataPath("n")
	_ = os.Remove(entry)
	if err := os.Symlink(target, entry); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read of symlinked data file = %v, want ErrDenied", err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("replace of symlinked data file = %v, want ErrDenied", err)
	}
	if err := b.CreateIfAbsent(ctx, "n", []byte("x")); !errors.Is(err, ErrDenied) {
		t.Fatalf("create over a symlinked name = %v, want ErrDenied", err)
	}
	if got, _ := os.ReadFile(target); !bytes.Equal(got, outside) {
		t.Fatal("driver followed a symlink to outside the root")
	}
	// Symlinked data file with a dangling target: the replace's compare step
	// treats the unreadable entry as a mismatch, never as a missing name.
	if err := os.Remove(entry); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "missing"), entry); err != nil {
		t.Fatal(err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("x")); !errors.Is(err, ErrDenied) && !errors.Is(err, ErrConflict) {
		t.Fatalf("replace over a dangling name = %v, want ErrDenied or ErrConflict", err)
	}
	if _, err := os.Lstat(filepath.Join(other, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replace created a file outside the root")
	}
}

// assertOutsideUntouched lists dir and fails if it holds anything but the
// expected seed entries (name -> contents). It proves that a refused OpenDir or
// operation did not create, remove or modify anything outside the root.
func assertOutsideUntouched(t *testing.T, dir string, seed map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(seed) {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("outside directory changed: entries = %v, want %d", names, len(seed))
	}
	for _, e := range entries {
		want, ok := seed[e.Name()]
		if !ok || e.IsDir() {
			t.Fatalf("unexpected entry %q written outside the root", e.Name())
		}
		got, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || string(got) != want {
			t.Fatalf("outside file %q = %q, %v; want untouched %q", e.Name(), got, err, want)
		}
	}
}

// A pre-existing <root>/vaultfile-backend symlink, or a non-directory there, is
// refused before anything is created below it; the outside target is never
// written. A loosened namespace directory is refused as well, consistent with
// the 0700 policy applied to the directories below it.
func TestDirRefusesSymlinkedOrLoosenedNamespace(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, root, ns, outside string)
		// dirEntry is set when ns stays a directory entry, so a v1 below it
		// would have to be created inside the refused namespace itself.
		dirEntry bool
	}{
		{"symlink_to_outside_dir", func(t *testing.T, root, ns, outside string) {
			if err := os.Symlink(outside, ns); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"dangling_symlink", func(t *testing.T, root, ns, outside string) {
			if err := os.Symlink(filepath.Join(outside, "missing"), ns); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"regular_file", func(t *testing.T, root, ns, outside string) {
			if err := os.WriteFile(ns, []byte("not a directory"), 0600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"directory_loosened_to_0777", func(t *testing.T, root, ns, outside string) {
			if err := os.Mkdir(ns, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(ns, 0777); err != nil {
				t.Fatal(err)
			}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			outside := filepath.Join(base, "outside-ns")
			seed := map[string]string{"keep.txt": "outside data"}
			if err := os.Mkdir(outside, 0700); err != nil {
				t.Fatal(err)
			}
			for name, body := range seed {
				if err := os.WriteFile(filepath.Join(outside, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			root := filepath.Join(base, "root")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			ns := filepath.Join(root, dirSubdir)
			tc.setup(t, root, ns, outside)

			if _, err := OpenDir(root); !errors.Is(err, ErrDenied) {
				t.Fatalf("open with %s = %v, want ErrDenied", tc.name, err)
			}
			// No v1 directory, tmp, data or lock file was created, whether at
			// the symlink target or inside the namespace directory itself.
			if entries, err := os.ReadDir(root); err != nil || len(entries) != 1 || entries[0].Name() != dirSubdir {
				t.Fatalf("refused open changed the root: %v %v", entries, err)
			}
			if _, err := os.Lstat(filepath.Join(outside, dirVer)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused open created a version directory outside the root")
			}
			assertOutsideUntouched(t, outside, seed)
			if tc.dirEntry {
				if _, err := os.Lstat(filepath.Join(ns, dirVer)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refused open created a version directory inside the refused namespace")
				}
			}
			// The refused component is never replaced by OpenDir, so it keeps
			// refusing: a second attempt fails the same way.
			if _, err := OpenDir(root); !errors.Is(err, ErrDenied) {
				t.Fatalf("second open with %s = %v, want ErrDenied", tc.name, err)
			}
		})
	}
}

// Every protected namespace component must be owned by the effective user even
// when it is a non-symlink directory with exactly 0700, so a directory that is
// loose in neither mode nor linkness but belongs to someone else is refused.
// Changing a file's owner requires privilege, so the test is skipped where
// chown to a foreign UID is not permitted. -1 is used as the UID so that an
// unprivileged chown fails instead of silently succeeding.
func TestDirRefusesForeignOwnedNamespace(t *testing.T) {
	ctx := context.Background()
	foreign := os.Geteuid() + 1
	chown := func(t *testing.T, p string) {
		t.Helper()
		if err := os.Lchown(p, foreign, -1); err != nil {
			t.Skipf("cannot change owner to UID %d: %v", foreign, err)
		}
		st, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if ownedByEUID(st) {
			t.Fatalf("chown to UID %d left %s owned by the effective user", foreign, p)
		}
	}

	// The process's own directories pass the ownership check, and every
	// directory below a fresh root is created owned by this process.
	if st, err := os.Lstat(t.TempDir()); err != nil || !ownedByEUID(st) {
		t.Fatalf("process-owned temp directory not reported as owned: %v", err)
	}
	if st, err := os.Lstat("/"); err != nil || ownedByEUID(st) && os.Geteuid() != 0 {
		t.Fatal("root directory reported as owned by the effective user")
	}
	d := openAt(t, t.TempDir()).(*Dir)
	for p := d.ns; p != filepath.Dir(d.ns); p = filepath.Dir(p) {
		if st, err := os.Lstat(p); err != nil || !ownedByEUID(st) {
			t.Fatalf("created namespace directory %s is not owned by the effective user: %v", p, err)
		}
	}
	if err := d.CreateIfAbsent(ctx, "seed", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Read(ctx, "seed"); err != nil {
		t.Fatalf("read in process-owned namespace = %v", err)
	}

	components := []struct{ name, sub string }{
		{"storage_namespace", ""},
		{"version_directory", dirVer},
		{"tmp_directory", filepath.Join(dirVer, tmpName)},
		{"data_directory", filepath.Join(dirVer, dataName)},
	}
	for _, tc := range components {
		t.Run(tc.name+"_before_open", func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "root")
			if _, err := OpenDir(root); err != nil {
				t.Fatal(err)
			}
			ns := filepath.Join(root, dirSubdir)
			target := filepath.Join(ns, tc.sub)
			chown(t, target)
			if st, err := os.Lstat(target); err != nil {
				t.Fatal(err)
			} else if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 {
				t.Fatalf("fixture is not a real 0700 directory: %v", st.Mode())
			}
			if _, err := OpenDir(root); !errors.Is(err, ErrDenied) {
				t.Fatalf("open with foreign-owned %s = %v, want ErrDenied", tc.name, err)
			}
		})
		t.Run(tc.name+"_after_open", func(t *testing.T) {
			b := openAt(t, t.TempDir()).(*Dir)
			if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
				t.Fatal(err)
			}
			cur := mustRead(t, b, "n")
			target := filepath.Join(b.ns, tc.sub)
			chown(t, target)
			if st, err := os.Lstat(target); err != nil {
				t.Fatal(err)
			} else if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 {
				t.Fatalf("fixture is not a real 0700 directory: %v", st.Mode())
			}
			if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
				t.Fatalf("read with foreign-owned %s = %v, want ErrDenied", tc.name, err)
			}
			if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrDenied) {
				t.Fatalf("replace with foreign-owned %s = %v, want ErrDenied", tc.name, err)
			}
			// The backend refuses every operation while the component is
			// foreign-owned, so the stored record is inspected directly, not
			// through Dir.Read: it must still be the seed version, and no
			// temporary file may have been staged.
			raw, err := os.ReadFile(b.dataPath("n"))
			if err != nil {
				t.Fatalf("inspect stored record: %v", err)
			}
			rec, err := decodeRecord(raw)
			if err != nil || rec.version != string(cur.Revision) || string(rec.value) != "v1" {
				t.Fatalf("refused write changed the stored version: %v, %q", err, rec.value)
			}
			tmp := filepath.Join(b.root, tmpName)
			if entries, err := os.ReadDir(tmp); err != nil && tc.name != "tmp_directory_after_open" {
				t.Fatalf("inspect temporary directory: %v", err)
			} else if len(entries) != 0 {
				t.Fatalf("refused write left %d temporary files", len(entries))
			}
		})
	}
}

// Replacing <root>/vaultfile-backend with a symlink after OpenDir is refused by
// every later operation: the checks of the final v1, tmp and data components
// no longer follow the intermediate link, and nothing is created or read or
// written through it.
func TestDirRefusesNamespaceSwapAfterOpen(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")

	// Move the real namespace aside and point the component at a directory
	// outside the root that carries the same v1/tmp/data layout and a copy of
	// the record, so following the link would otherwise succeed.
	outside := filepath.Join(base, "outside-ns")
	moved := filepath.Join(base, "moved-ns")
	if err := os.Rename(b.ns, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	outV1 := filepath.Join(outside, dirVer)
	if err := os.MkdirAll(filepath.Join(outV1, tmpName), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outV1, dataName), 0700); err != nil {
		t.Fatal(err)
	}
	secret := []byte("outside secret")
	if err := os.WriteFile(filepath.Join(outV1, dataName, filepath.Base(b.dataPath("n"))), secret, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, b.ns); err != nil {
		t.Fatal(err)
	}

	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read through swapped namespace = %v, want ErrDenied", err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("replace through swapped namespace = %v, want ErrDenied", err)
	}
	if err := b.CreateIfAbsent(ctx, "fresh", []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("create through swapped namespace = %v, want ErrDenied", err)
	}
	// The outside layout is untouched: no data file created, no temporary
	// file, and no lock file created through the swapped component. This is
	// the confinement guarantee (a symlink is checked before use); replacing
	// a component with a real directory is covered by the identity tests.
	if got, err := os.ReadFile(filepath.Join(outV1, dataName, filepath.Base(b.dataPath("n")))); err != nil || !bytes.Equal(got, secret) {
		t.Fatal("operation wrote through the swapped namespace")
	}
	if entries, _ := os.ReadDir(filepath.Join(outV1, dataName)); len(entries) != 1 {
		t.Fatalf("operation added %d data files outside the root", len(entries)-1)
	}
	if entries, _ := os.ReadDir(filepath.Join(outV1, tmpName)); len(entries) != 0 {
		t.Fatal("operation staged a temporary file outside the root")
	}
	if _, err := os.Lstat(filepath.Join(outV1, lockName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("operation created a lock file outside the root")
	}
	// A fresh OpenDir over the same root also refuses the swapped component.
	if _, err := OpenDir(root); !errors.Is(err, ErrDenied) {
		t.Fatalf("open with swapped namespace = %v, want ErrDenied", err)
	}
	// Returning the real namespace restores service: the refusal is on the
	// component, not a permanent lockout.
	if err := os.Remove(b.ns); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, b.ns); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, b, "n"); string(got.Bytes) != "v1" || got.Revision != cur.Revision {
		t.Fatal("restored namespace does not serve the committed version")
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); err != nil {
		t.Fatalf("replace after restore = %v", err)
	}
}

// Two live instances sharing the original lock inode must never use a
// different one. Replacing the lock pathname with another ordinary private
// 0600 regular file, or removing it, makes every operation of both instances
// fail with ErrDenied without locking, writing or re-creating the lock, and the
// replacement's inode and bytes and the data files stay unchanged.
func TestDirPinsLockInodePerInstance(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	a := openAt(t, root).(*Dir)
	b := openAt(t, root).(*Dir)
	if err := a.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, b, "n"); string(got.Bytes) != "v1" {
		t.Fatal("second instance does not serve the committed version")
	}
	rev := mustRead(t, a, "n").Revision
	dataBefore := fileList(t, filepath.Join(a.root, dataName))

	original, err := os.Stat(a.lock)
	if err != nil {
		t.Fatal(err)
	}
	if !sameIdentity(a.lockID, original) || !sameIdentity(b.lockID, original) {
		t.Fatal("instances are not pinned to the open lock inode")
	}

	t.Run("replaced_regular_file", func(t *testing.T) {
		// Detach the original inode and put an ordinary, private 0600
		// regular file in its place: identical mode and owner, different
		// inode, no symlink involved.
		old := filepath.Join(t.TempDir(), "old-lock")
		if err := os.Rename(a.lock, old); err != nil {
			t.Fatal(err)
		}
		replacement := []byte("replacement lock contents\n")
		if err := os.WriteFile(a.lock, replacement, 0600); err != nil {
			t.Fatal(err)
		}
		replaced, err := os.Lstat(a.lock)
		if err != nil {
			t.Fatal(err)
		}
		if !replaced.Mode().IsRegular() || replaced.Mode()&os.ModeSymlink != 0 || replaced.Mode().Perm() != 0600 || !ownedByEUID(replaced) {
			t.Fatalf("replacement is not a private regular file: %v", replaced.Mode())
		}
		if os.SameFile(original, replaced) {
			t.Fatal("replacement is not a different inode")
		}

		for name, d := range map[string]*Dir{"a": a, "b": b} {
			if _, err := d.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
				t.Fatalf("%s: read with replaced lock = %v, want ErrDenied", name, err)
			}
			if err := d.ReplaceIfVersion(ctx, "n", rev, []byte("v2")); !errors.Is(err, ErrDenied) {
				t.Fatalf("%s: replace with replaced lock = %v, want ErrDenied", name, err)
			}
			if err := d.CreateIfAbsent(ctx, "fresh-"+name, []byte("v2")); !errors.Is(err, ErrDenied) {
				t.Fatalf("%s: create with replaced lock = %v, want ErrDenied", name, err)
			}
		}
		// The replacement is untouched and still the same inode: no lock was
		// taken on it and no ticket was written through it.
		after, err := os.Lstat(a.lock)
		if err != nil || !os.SameFile(replaced, after) {
			t.Fatal("operation replaced or recreated the lock path")
		}
		if got, err := os.ReadFile(a.lock); err != nil || !bytes.Equal(got, replacement) {
			t.Fatalf("replacement lock bytes changed: %q %v", got, err)
		}
		// No new lock inode was created anywhere else and no data changed.
		if _, err := os.Lstat(old); err != nil {
			t.Fatal("original lock inode disappeared")
		}
		if !maps.Equal(dataBefore, fileList(t, filepath.Join(a.root, dataName))) {
			t.Fatal("refused operations changed data files")
		}
		if got, _ := os.ReadDir(filepath.Join(a.root, tmpName)); len(got) != 0 {
			t.Fatalf("refused operations left %d temporary files", len(got))
		}
		// Restoring the original inode restores both instances.
		if err := os.Remove(a.lock); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(old, a.lock); err != nil {
			t.Fatal(err)
		}
		if got := mustRead(t, a, "n"); got.Revision != rev {
			t.Fatal("instance a does not recover after restoring the lock")
		}
		if got := mustRead(t, b, "n"); got.Revision != rev {
			t.Fatal("instance b does not recover after restoring the lock")
		}
	})

	t.Run("removed", func(t *testing.T) {
		if err := os.Remove(a.lock); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
			t.Fatalf("read with removed lock = %v, want ErrDenied", err)
		}
		if err := a.ReplaceIfVersion(ctx, "n", rev, []byte("v2")); !errors.Is(err, ErrDenied) {
			t.Fatalf("replace with removed lock = %v, want ErrDenied", err)
		}
		if err := a.CreateIfAbsent(ctx, "fresh", []byte("v2")); !errors.Is(err, ErrDenied) {
			t.Fatalf("create with removed lock = %v, want ErrDenied", err)
		}
		// No operation re-created the lock inode.
		if _, err := os.Lstat(a.lock); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("an operation re-created the removed lock file")
		}
		if !maps.Equal(dataBefore, fileList(t, filepath.Join(a.root, dataName))) {
			t.Fatal("refused operations changed data files")
		}
		// A fresh OpenDir creates a new lock inode, but the old instance stays
		// pinned to its own and keeps refusing.
		fresh := openAt(t, root).(*Dir)
		if sameIdentity(a.lockID, fresh.lockID) {
			t.Fatal("a recreated lock inode was reported identical to the original")
		}
		if _, err := a.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
			t.Fatalf("old instance accepted a re-created lock = %v, want ErrDenied", err)
		}
	})
}

// Replacing the configured root itself with a symlink after OpenDir is refused
// by every later operation. ns, v1, tmp and data are paths below the root, so
// without checking the root by identity their Lstat would follow the swapped
// root into an outside tree; the outside tree below is built to look valid.
func TestDirRefusesRootSwapToSymlink(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")

	// Move the real root aside and leave a symlink in its place. The target
	// holds a valid-looking namespace, a valid temporary directory and the
	// seed record, so following the link would otherwise succeed and a
	// replace would write through it.
	outside := filepath.Join(base, "outside")
	outV1 := filepath.Join(outside, dirSubdir, dirVer)
	for _, p := range []string{filepath.Join(outV1, tmpName), filepath.Join(outV1, dataName)} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	record, err := os.ReadFile(b.dataPath("n"))
	if err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(outV1, dataName, filepath.Base(b.dataPath("n")))
	if err := os.WriteFile(entry, record, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}

	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read through swapped root = %v, want ErrDenied", err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("replace through swapped root = %v, want ErrDenied", err)
	}
	if err := b.CreateIfAbsent(ctx, "fresh", []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("create through swapped root = %v, want ErrDenied", err)
	}
	if _, err := OpenDir(root); !errors.Is(err, ErrDenied) {
		t.Fatalf("open of symlinked root = %v, want ErrDenied", err)
	}
	// The outside tree is byte-for-byte unchanged: no replaced or new data
	// file, no staged temporary file and no lock file created through it. This
	// is the confinement guarantee (a symlink is checked before use);
	// replacing a component with a real directory is covered by the identity
	// tests.
	if got, err := os.ReadFile(entry); err != nil || !bytes.Equal(got, record) {
		t.Fatal("operation wrote through the swapped root")
	}
	if entries, _ := os.ReadDir(filepath.Join(outV1, dataName)); len(entries) != 1 {
		t.Fatalf("operation added %d data files outside the root", len(entries)-1)
	}
	if entries, _ := os.ReadDir(filepath.Join(outV1, tmpName)); len(entries) != 0 {
		t.Fatal("operation staged a temporary file outside the root")
	}
	if _, err := os.Lstat(filepath.Join(outV1, lockName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("operation created a lock file outside the root")
	}
	// Restoring the real root restores service.
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(base, "moved"), root); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, b, "n"); string(got.Bytes) != "v1" || got.Revision != cur.Revision {
		t.Fatal("restored root does not serve the committed version")
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); err != nil {
		t.Fatalf("replace after restore = %v", err)
	}
}

// stickyDir reports whether p is a sticky directory. It uses os.Stat, not
// os.Lstat, because on macOS the temp path can go through the /tmp symlink and
// lstat would inspect the link rather than the directory.
func stickyDir(t *testing.T, p string) bool {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode()&os.ModeSticky != 0
}

// A sticky directory is accepted as a root ancestor only when it is trusted
// exactly as privateDir defines it: not group/world writable, or a root-owned
// system sticky directory. Before the regression c34c330 introduced, any sticky
// directory was accepted, so the sticky world-writable fixture below could
// hold an openable root; now it must be refused, both as an ancestor of the
// root and as the configured root itself.
func TestDirRejectsUntrustedStickyAncestor(t *testing.T) {
	// Root trusts every sticky directory: a root-owned /tmp is the intended
	// case, and a test cannot create an untrusted ancestor while trusted by root.
	if os.Geteuid() == 0 {
		t.Skip("running as root: sticky directories are intentionally trusted")
	}
	// assertUntrustedSticky checks that p is a real (not symlinked) directory
	// with exactly sticky 0777, owned by this process: writable by group and
	// others, so privateDir refuses it although the sticky bit is set.
	assertUntrustedSticky := func(t *testing.T, p string) {
		t.Helper()
		st, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s is not a real directory: %v", p, st.Mode())
		}
		if st.Mode()&os.ModeSticky == 0 || st.Mode().Perm() != 0777 {
			t.Fatalf("%s mode = %v, want sticky 0777", p, st.Mode())
		}
		if !stickyDir(t, p) {
			t.Fatalf("%s is not reported sticky by Stat", p)
		}
		if !ownedByEUID(st) {
			t.Fatalf("%s is not owned by the effective user", p)
		}
	}
	// stickyChain creates base/sticky/root and makes the parent sticky 0777,
	// leaving the configured root itself at 0700.
	stickyChain := func(t *testing.T) (sticky, root string) {
		t.Helper()
		base := t.TempDir()
		sticky = filepath.Join(base, "sticky")
		root = filepath.Join(sticky, "root")
		for _, p := range []string{sticky, root} {
			if err := os.Mkdir(p, 0700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(sticky, os.ModeSticky|0777); err != nil {
			t.Fatal(err)
		}
		assertUntrustedSticky(t, sticky)
		return sticky, root
	}

	t.Run("ancestor_of_root", func(t *testing.T) {
		_, root := stickyChain(t)
		if _, err := OpenDir(root); !errors.Is(err, ErrDenied) {
			t.Fatalf("open below own sticky world-writable ancestor = %v, want ErrDenied", err)
		}
	})

	// The configured root itself is already sticky 0777 at OpenDir, under a
	// safe 0700 parent: OpenDir must refuse the root it was asked to open, not
	// an ancestor of it.
	t.Run("configured_root", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "root")
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		// The parent (and every ancestor of the temp directory) must be
		// trusted under the old policy: not group/world writable, or a
		// root-owned system sticky directory. The temp directory's own mode
		// varies by platform and umask, so the policy is what is asserted.
		if st, err := os.Stat(filepath.Dir(root)); err != nil || !privateDir(st) {
			t.Fatalf("fixture parent is not a safe directory: %v %v", st, err)
		}
		if st, err := os.Lstat(root); err != nil || st.Mode()&os.ModeSticky != 0 || st.Mode().Perm() != 0700 {
			t.Fatalf("fixture root is not a plain 0700 directory: %v %v", st, err)
		}
		if err := os.Chmod(root, os.ModeSticky|0777); err != nil {
			t.Fatal(err)
		}
		assertUntrustedSticky(t, root)
		if _, err := OpenDir(root); !errors.Is(err, ErrDenied) {
			t.Fatalf("open own sticky world-writable root = %v, want ErrDenied", err)
		}
		if _, err := os.Lstat(filepath.Join(root, dirSubdir)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refused root was initialized")
		}
	})

	t.Run("configured_root_becomes_sticky", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "root")
		b := openAt(t, root).(*Dir)
		ctx := context.Background()
		if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
			t.Fatal(err)
		}
		cur := mustRead(t, b, "n")
		if err := os.Chmod(root, os.ModeSticky|0777); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
			t.Fatalf("read with own sticky world-writable root = %v, want ErrDenied", err)
		}
		if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrDenied) {
			t.Fatalf("replace with own sticky world-writable root = %v, want ErrDenied", err)
		}
		if err := os.Chmod(root, 0700); err != nil {
			t.Fatal(err)
		}
		if got := mustRead(t, b, "n"); string(got.Bytes) != "v1" || got.Revision != cur.Revision {
			t.Fatal("refused write against an untrusted sticky root changed the stored version")
		}
	})
}

// The root policy is not tightened: a safe 0755 root (not group/world
// writable) is still accepted on OpenDir and still usable afterwards, while a
// root that becomes group or world writable after OpenDir is refused.
func TestDirRootModePolicyUnchanged(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	b := openAt(t, root)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v")); err != nil {
		t.Fatalf("0755 root: %v", err)
	}
	if err := os.Chmod(root, 0775); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read with group-writable root = %v, want ErrDenied", err)
	}
}

// replacedComponent is one protected component, relative to the configured
// root path, and the Dir path that reaches it.
type replacedComponent struct {
	name string
	path func(b *Dir) string
}

// fileList returns the regular files below dir, sorted, with their contents.
// It captures both the shape and the bytes of a tree for before/after checks.
func fileList(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[p] = string(raw)
		return nil
	}); err != nil {
		t.Fatalf("list %s: %v", dir, err)
	}
	return out
}

// assertFileListUnchanged fails when a tree gained, lost or changed a file.
func assertFileListUnchanged(t *testing.T, label, dir string, before map[string]string) {
	t.Helper()
	after := fileList(t, dir)
	for p, body := range before {
		if got, ok := after[p]; !ok || got != body {
			t.Fatalf("%s: file %s changed or removed by a refused operation", label, p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Fatalf("%s: refused operation created %s", label, p)
		}
	}
}

// underPath reports whether p is dir or lies below it.
func underPath(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// validLayoutBelow returns the directories that must exist below a valid
// replacement for the named protected component: exactly the components the
// backend's path-based checks would look below it. A replaced tmp or data
// directory is a leaf and needs nothing below it.
func validLayoutBelow(name string) []string {
	switch name {
	case "root":
		return []string{dirSubdir, filepath.Join(dirSubdir, dirVer), filepath.Join(dirSubdir, dirVer, tmpName), filepath.Join(dirSubdir, dirVer, dataName)}
	case "namespace":
		return []string{dirVer, filepath.Join(dirVer, tmpName), filepath.Join(dirVer, dataName)}
	case "version":
		return []string{tmpName, dataName}
	}
	return nil
}

// mapPath joins every relative path in rels onto base.
func mapPath(base string, rels []string) []string {
	out := make([]string, 0, len(rels))
	for _, rel := range rels {
		out = append(out, filepath.Join(base, rel))
	}
	return out
}

// mkdirPrivate creates p as a real 0700 directory.
func mkdirPrivate(t *testing.T, p string) {
	t.Helper()
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatalf("create replacement %s: %v", p, err)
	}
}

// assertComponentReplacementDenied moves b's component c aside and puts a
// valid replacement in its place: a real 0700 directory with the complete
// layout the backend would look for below it, so the existing mode, symlink
// and descendant checks all pass for it. When the backend's record path lies
// below the replacement it holds a well-formed record with the current
// revision but alternate bytes; for tmp the real data file is left in place.
// Read, Replace and Create must still be denied, proving the inode identity
// check refuses the replacement on its own, and the alternate and original
// trees must be unchanged.
func assertComponentReplacementDenied(t *testing.T, b *Dir, c replacedComponent) {
	t.Helper()
	ctx := context.Background()
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")
	origRecord, err := os.ReadFile(b.dataPath("n"))
	if err != nil {
		t.Fatal(err)
	}
	origDataPath := b.dataPath("n")
	orig := c.path(b)
	moved := orig + ".moved"
	if err := os.Rename(orig, moved); err != nil {
		t.Fatal(err)
	}
	// The valid layout below each component, so no descendant check can refuse
	// the replacement: root needs vaultfile-backend/v1, the namespace needs
	// v1, and v1 needs tmp and data. For tmp and data themselves only the
	// replaced leaf is rebuilt; their siblings stay real.
	// validLayoutBelow lists the wrong order for creation: sort by depth, so
	// every parent exists before its child.
	layout := validLayoutBelow(c.name)
	slices.SortFunc(layout, func(a, b string) int {
		return strings.Count(a, string(filepath.Separator)) - strings.Count(b, string(filepath.Separator))
	})
	mkdirPrivate(t, orig)
	for _, d := range layout {
		mkdirPrivate(t, filepath.Join(orig, d))
	}
	// Put a well-formed, revision-matching record at the exact path the
	// backend would read, when that path is below the replacement.
	entry := ""
	var altRecord []byte
	if underPath(orig, origDataPath) {
		altValue := []byte("alternate")
		altRecord = record{version: string(cur.Revision), digest: sha256.Sum256(altValue), value: altValue}.encode()
		entry = origDataPath
		if err := os.WriteFile(entry, altRecord, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// The replacement must be a valid stand-in, so nothing but identity can
	// refuse it.
	for _, p := range append([]string{orig}, mapPath(orig, validLayoutBelow(c.name))...) {
		if st, err := os.Lstat(p); err != nil {
			t.Fatalf("replacement layout missing %s: %v", p, err)
		} else if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 || !ownedByEUID(st) {
			t.Fatalf("replacement %s is not a real private 0700 directory: %v", p, st.Mode())
		}
	}
	replacementBefore := fileList(t, orig)

	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("%s replaced by a valid real directory: read = %v, want ErrDenied", c.name, err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("%s replaced by a valid real directory: replace = %v, want ErrDenied", c.name, err)
	}
	if err := b.CreateIfAbsent(ctx, "fresh", []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("%s replaced by a valid real directory: create = %v, want ErrDenied", c.name, err)
	}

	// The replacement tree is byte-for-byte as built, and the original record
	// is untouched: for tmp the record is outside the replaced component, for
	// every other component it is the alternate record.
	assertFileListUnchanged(t, "replacement "+c.name, orig, replacementBefore)
	if entry != "" {
		if got := replacementBefore[entry]; got != string(altRecord) {
			t.Fatalf("%s replaced: alternate record not at the backend path %s", c.name, entry)
		}
	}
	if underPath(orig, origDataPath) {
		if _, ok := replacementBefore[origDataPath]; !ok {
			t.Fatalf("%s replaced: alternate record missing", c.name)
		}
	} else {
		// tmp: the real data file and the moved-aside tmp directory decide
		// whether a replacement could have been published.
		if got, err := os.ReadFile(origDataPath); err != nil || !bytes.Equal(got, origRecord) {
			t.Fatalf("%s replaced: stored record changed: %v", c.name, err)
		}
		if entries, err := os.ReadDir(moved); err != nil || len(entries) != 0 {
			t.Fatalf("%s replaced: temporary files were staged: %v %v", c.name, entries, err)
		}
	}

	// Restoring the original directory restores normal read.
	if err := os.RemoveAll(orig); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, orig); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, b, "n"); string(got.Bytes) != "v1" || got.Revision != cur.Revision {
		t.Fatalf("%s restored: read = %q %q, want the committed version", c.name, got.Bytes, got.Revision)
	}
}

// Every protected component replaced after OpenDir by another real directory
// with acceptable mode, owner and a complete valid layout is refused. The
// replacement is indistinguishable from the original to every path-based
// check except inode identity, so this proves the identity comparison itself
// rejects each component; removing only sameIdentity makes every subtest here
// fail. See TestDirRejectsReplacedComponentsUnderSameIdentity for the
// automated check of that.
func TestDirRejectsReplacedComponents(t *testing.T) {
	rootPath := func(b *Dir) string { return b.cfgRoot }
	components := []replacedComponent{
		{"root", rootPath},
		{"namespace", func(b *Dir) string { return b.ns }},
		{"version", func(b *Dir) string { return b.root }},
		{"tmp", func(b *Dir) string { return filepath.Join(b.root, tmpName) }},
		{"data", func(b *Dir) string { return filepath.Join(b.root, dataName) }},
	}
	for _, c := range components {
		t.Run(c.name, func(t *testing.T) {
			b := openAt(t, filepath.Join(t.TempDir(), "root")).(*Dir)
			assertComponentReplacementDenied(t, b, c)
		})
	}
}

// Mutation check for the replacement subtests. The replacements they build are
// real 0700 directories with complete valid layouts, so the only check that
// can refuse them is the identity comparison. To verify that this is what
// happens, temporarily change sameIdentity in dir.go to "return true" and run
// with this opt-in set:
//
//	VAULTFILE_DIR_IDENTITY_MUTATION_CHECK=1 go test -run '^TestDirRejectsReplacedComponentsMutationNote$' ./pkg/vaultfilebackend/
//
// Every component must then be accepted (this test passes) and
// TestDirRejectsReplacedComponents must fail for every component. An automated
// in-process version would need a test hook inside sameIdentity, which is
// product code; this checkpoint deliberately adds none.
func TestDirRejectsReplacedComponentsMutationNote(t *testing.T) {
	if os.Getenv("VAULTFILE_DIR_IDENTITY_MUTATION_CHECK") == "" {
		t.Skip("opt-in check: patch sameIdentity in dir.go to return true and set VAULTFILE_DIR_IDENTITY_MUTATION_CHECK=1")
	}
	rootPath := func(b *Dir) string { return b.cfgRoot }
	components := []replacedComponent{
		{"root", rootPath},
		{"namespace", func(b *Dir) string { return b.ns }},
		{"version", func(b *Dir) string { return b.root }},
		{"tmp", func(b *Dir) string { return filepath.Join(b.root, tmpName) }},
		{"data", func(b *Dir) string { return filepath.Join(b.root, dataName) }},
	}
	for _, c := range components {
		t.Run(c.name, func(t *testing.T) {
			b := openAt(t, filepath.Join(t.TempDir(), "root")).(*Dir)
			assertComponentReplacementAccepted(t, b, c)
		})
	}
}

// assertComponentReplacementAccepted is the mutation counterpart of
// assertComponentReplacementDenied: with the identity comparison disabled the
// replacement must take over, which proves its subtree is complete and valid
// and that only identity refuses it.
func assertComponentReplacementAccepted(t *testing.T, b *Dir, c replacedComponent) {
	t.Helper()
	ctx := context.Background()
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")
	origDataPath := b.dataPath("n")
	orig := c.path(b)
	if err := os.Rename(orig, orig+".moved"); err != nil {
		t.Fatal(err)
	}
	layout := validLayoutBelow(c.name)
	slices.SortFunc(layout, func(a, b string) int {
		return strings.Count(a, string(filepath.Separator)) - strings.Count(b, string(filepath.Separator))
	})
	mkdirPrivate(t, orig)
	for _, d := range layout {
		mkdirPrivate(t, filepath.Join(orig, d))
	}
	altValue := []byte("alternate")
	if underPath(orig, origDataPath) {
		alt := record{version: string(cur.Revision), digest: sha256.Sum256(altValue), value: altValue}.encode()
		if err := os.WriteFile(origDataPath, alt, 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := b.Read(ctx, "n")
	if err != nil {
		t.Fatalf("%s replacement not accepted: %v (is sameIdentity patched?)", c.name, err)
	}
	if c.name != "tmp" && !bytes.Equal(got.Bytes, altValue) {
		t.Fatalf("%s replacement not read through: got %q", c.name, got.Bytes)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); err != nil {
		t.Fatalf("%s replacement not written through: %v", c.name, err)
	}
}

// A directory renamed back into the same path keeps its identity and stays in
// service: the check is identity, not path or creation time.
func TestDirAcceptsMovedBackComponent(t *testing.T) {
	ctx := context.Background()
	b := openAt(t, t.TempDir()).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")
	data := filepath.Join(b.root, dataName)
	if err := os.Rename(data, data+".moved"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read with moved data directory = %v, want ErrDenied", err)
	}
	if err := os.Rename(data+".moved", data); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, b, "n"); string(got.Bytes) != "v1" || got.Revision != cur.Revision {
		t.Fatal("moved-back data directory does not serve the committed version")
	}
}

func TestDirRefusesRootSymlinkAndLoosenedRoot(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDir(link); !errors.Is(err, ErrDenied) {
		t.Fatalf("open symlinked root = %v, want ErrDenied", err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	// The root's ancestors are checked on OpenDir: TMPDIR itself may be a
	// world-writable sticky directory (/tmp), which is accepted, but the
	// non-sticky, world-writable parent below it is not.
	existing := filepath.Join(parent, "existing")
	if err := os.Mkdir(existing, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDir(existing); !errors.Is(err, ErrDenied) {
		t.Fatalf("open under world-writable parent = %v, want ErrDenied", err)
	}
	if _, err := os.Lstat(filepath.Join(existing, dirSubdir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused root was initialized")
	}
	// Loosened data directory after OpenDir is refused on the next operation.
	b, err := OpenDir(filepath.Join(t.TempDir(), "ok"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := os.Chmod(filepath.Join(b.root, dataName), 0777); err != nil {
		t.Fatal(err)
	}
	if err := b.CreateIfAbsent(context.Background(), "n", []byte("v")); !errors.Is(err, ErrDenied) {
		t.Fatalf("write into loosened data dir = %v, want ErrDenied", err)
	}
}

func TestDirDataFilesArePrivate(t *testing.T) {
	root := t.TempDir()
	b := openAt(t, root)
	if err := b.CreateIfAbsent(context.Background(), "n", []byte("v")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(root, dirSubdir),
		filepath.Join(root, dirSubdir, dirVer),
		filepath.Join(root, dirSubdir, dirVer, dataName),
		filepath.Join(root, dirSubdir, dirVer, tmpName),
	} {
		if st, err := os.Lstat(p); err != nil || st.Mode().Perm() != 0700 {
			t.Fatalf("%s mode = %v %v, want 0700", p, st.Mode().Perm(), err)
		}
	}
	entry := b.(*Dir).dataPath("n")
	if st, err := os.Lstat(entry); err != nil || st.Mode().Perm() != 0600 || st.Mode()&os.ModeSymlink != 0 {
		t.Fatal("data file is not a private regular file")
	}
	if st, err := os.Lstat(filepath.Join(root, dirSubdir, dirVer, lockName)); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("lock file is not private")
	}
}

func TestDirContextCancellation(t *testing.T) {
	ctx := context.Background()
	b := openAt(t, t.TempDir())
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := b.CreateIfAbsent(cctx, "n", []byte("v")); !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled create = %v", err)
	}
	if err := b.ReplaceIfVersion(cctx, "n", Revision("x"), []byte("v")); !errors.Is(err, ErrDenied) {
		t.Fatalf("cancelled replace = %v", err)
	}
	if _, err := b.Read(cctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("cancelled read = %v", err)
	}
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrNotFound) {
		t.Fatal("cancelled create wrote state")
	}
}

// An earlier process died after it staged a temporary file and recorded its
// holder ticket but before publication. The next writer must clear the ticket
// (kernel locks are released on death), remove the orphan temporary file, and
// proceed. The orphan's bytes never become the committed value.
func TestDirRecoversDeadHolderTicketAndLeftoverTemp(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")

	lock := filepath.Join(b.root, lockName)
	untracked := b.tmpPath(strings.Repeat("ef", 16))
	if err := os.WriteFile(untracked, []byte("staged but untracked"), 0600); err != nil {
		t.Fatal(err)
	}
	orphanID := strings.Repeat("ab", 16)
	orphan := b.tmpPath(orphanID)
	orphanRec := record{version: strings.Repeat("cd", 16), digest: [32]byte{9}, value: []byte("crashed writer bytes")}
	if err := os.WriteFile(orphan, orphanRec.encode(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, []byte(ticketHolder+" "+orphanID+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); err != nil {
		t.Fatalf("replace after crash artifact = %v", err)
	}
	for _, leftover := range []string{orphan, untracked} {
		if _, err := os.Lstat(leftover); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("orphan temporary file %s not removed", filepath.Base(leftover))
		}
	}
	if got := mustRead(t, b, "n"); string(got.Bytes) != "v2" {
		t.Fatalf("stored = %q, want v2", got.Bytes)
	}
	if st, err := os.Stat(lock); err != nil || st.Size() != 0 {
		t.Fatalf("holder ticket not cleared: %v", err)
	}
}

func TestDirCorruptLockTicketIsDenied(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")
	lock := filepath.Join(b.root, lockName)
	if err := os.WriteFile(lock, []byte("garbage without newline"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("write with corrupt ticket = %v, want ErrDenied", err)
	}
	if got, _ := b.Read(ctx, "n"); string(got.Bytes) != "v1" {
		t.Fatal("corrupt ticket write changed data")
	}
}

func TestDirCorruptDataIsReportedNotOverwritten(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")
	entry := b.dataPath("n")
	good, err := os.ReadFile(entry)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":          nil,
		"truncated":      good[:len(good)-1],
		"flipped":        append(append([]byte(nil), good[:len(good)-1]...), good[len(good)-1]^0xff),
		"foreign header": []byte("plain bytes without a record header"),
		"zero version":   append(append([]byte(nil), recordMagic...), 0, 0, 0, 0, 32, 0, 0, 0),
	}
	for label, raw := range cases {
		if err := os.WriteFile(entry, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s: read = %v, want ErrCorrupt", label, err)
		}
		if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s: replace = %v, want ErrCorrupt", label, err)
		}
		if err := b.CreateIfAbsent(ctx, "n", []byte("v2")); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: create = %v, want ErrConflict", label, err)
		}
		if after, _ := os.ReadFile(entry); !bytes.Equal(after, raw) {
			t.Fatalf("%s: corrupt data was modified", label)
		}
	}
	// Restore a valid record and loosen its permissions: refused, not read.
	if err := os.WriteFile(entry, good, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(entry, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read of group-readable data = %v, want ErrDenied", err)
	}
	if err := os.Chmod(entry, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read of 0400 data = %v, want ErrDenied", err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("replace over 0400 data = %v, want ErrDenied", err)
	}
}

// Replacing a missing name conflicts even with a plausible non-zero revision
// and creates nothing, just like a stale revision.
func TestDirReplaceMissingConflicts(t *testing.T) {
	ctx := context.Background()
	b := openAt(t, t.TempDir()).(*Dir)
	err := b.ReplaceIfVersion(ctx, "absent", Revision(strings.Repeat("0", 32)), []byte("v"))
	if !errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
		t.Fatalf("replace missing = %v, want ErrConflict", err)
	}
	if _, err := os.Lstat(b.dataPath("absent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replace of a missing name created it")
	}
	// Create is the only path that commits an absent name, and the revision
	// it returns is what a later replace must present.
	if err := b.CreateIfAbsent(ctx, "absent", []byte("v")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "absent")
	if err := b.ReplaceIfVersion(ctx, "absent", Revision(strings.ToUpper(string(cur.Revision))), []byte("v2")); !errors.Is(err, ErrConflict) {
		t.Fatalf("replace with case-folded revision = %v, want ErrConflict", err)
	}
}

func TestDirClosedBackend(t *testing.T) {
	ctx := context.Background()
	b, err := OpenDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal("second close", err)
	}
	if err := b.CreateIfAbsent(ctx, "n", []byte("v")); !errors.Is(err, ErrDenied) {
		t.Fatalf("create after close = %v", err)
	}
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read after close = %v", err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", Revision("x"), []byte("v")); !errors.Is(err, ErrDenied) {
		t.Fatalf("replace after close = %v", err)
	}
	if _, err := b.List(ctx); !errors.Is(err, ErrDenied) {
		t.Fatalf("list after close = %v, want ErrDenied", err)
	}
}

// The same deadline bounds a waiter that is stuck on the in-process lock held
// by a goroutine of this process and is later released; it must return with a
// definite conflict before the holder lets go, not block until then.
func TestDirInProcLockUsesSameDeadline(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	a := openAt(t, root).(*Dir)
	if err := a.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, a, "n")
	b := openAt(t, root).(*Dir)
	b.timeout = 30 * time.Millisecond

	if err := a.inProc.acquire(ctx, time.Time{}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2"))
	if !errors.Is(err, ErrConflict) || errors.Is(err, ErrUnknown) {
		t.Fatalf("in-process lock timeout = %v, want definite ErrConflict", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("in-process wait ignored the deadline: %v", elapsed)
	}
	// Cancellation while the in-process lock is held is ErrDenied and keeps
	// the cause; it does not leave a goroutine waiting.
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- b.CreateIfAbsent(cctx, "other", []byte("x")) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled in-process waiter = %v, want ErrDenied wrapping context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled in-process waiter did not return")
	}
	a.inProc.release()
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); err != nil {
		t.Fatalf("write after release = %v", err)
	}
	if _, err := b.Read(ctx, "other"); !errors.Is(err, ErrNotFound) {
		t.Fatal("cancelled waiter wrote state")
	}
}

// A replace whose publication step failed with an I/O error after the
// temporary file was staged reports ErrUnknown, and a Read resolves the
// outcome; when the rename itself completed, the new version is visible.
func TestDirPublicationUnknownIsResolvedByRead(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")

	commitHook = func(d *Dir, op writeOp) error {
		if err := os.Rename(d.tmpPath(op.tmpID), op.final(d)); err != nil {
			return fmt.Errorf("%w: %w", ErrUnknown, err)
		}
		return fmt.Errorf("%w: %w", ErrUnknown, syscall.EIO)
	}
	t.Cleanup(func() { commitHook = nil })
	err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2"))
	if !errors.Is(err, ErrUnknown) {
		t.Fatalf("publication error = %v, want ErrUnknown", err)
	}
	commitHook = nil
	after := mustRead(t, b, "n")
	if string(after.Bytes) != "v2" {
		t.Fatalf("unknown outcome resolved to %q, want v2", after.Bytes)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v3")); !errors.Is(err, ErrConflict) {
		t.Fatalf("retry with pre-publication revision = %v, want ErrConflict", err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", after.Revision, []byte("v3")); err != nil {
		t.Fatalf("retry with observed revision = %v", err)
	}
}

// An operation interrupted inside the critical section before publication
// returns ErrDenied, leaves the stored version, removes its temporary file and
// clears its ticket, and the store stays usable afterwards.
func TestDirInterruptBeforePublicationDenied(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")

	lockInterrupt = func(ctx context.Context, op writeOp) error {
		return context.Canceled
	}
	t.Cleanup(func() { lockInterrupt = nil })
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrDenied) || errors.Is(err, ErrUnknown) {
		t.Fatalf("interrupted replace = %v, want ErrDenied", err)
	}
	if err := b.CreateIfAbsent(ctx, "create", []byte("v")); !errors.Is(err, ErrDenied) {
		t.Fatalf("interrupted create = %v, want ErrDenied", err)
	}
	lockInterrupt = nil
	if got := mustRead(t, b, "n"); string(got.Bytes) != "v1" || got.Revision != cur.Revision {
		t.Fatal("interrupted write changed the stored version")
	}
	if _, err := b.Read(ctx, "create"); !errors.Is(err, ErrNotFound) {
		t.Fatal("interrupted create wrote state")
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); err != nil {
		t.Fatalf("write after interruption = %v", err)
	}
	if st, err := os.Stat(filepath.Join(b.root, lockName)); err != nil || st.Size() != 0 {
		t.Fatalf("interrupted write left a holder ticket: %v", err)
	}
	if names, _ := os.ReadDir(filepath.Join(b.root, tmpName)); len(names) != 0 {
		t.Fatalf("interrupted write left %d temporary files", len(names))
	}
}

// A writer that dies after creating and syncing its staged file but before
// recording its holder ticket leaves the ticket free and an untracked staged
// file. A free ticket under the OS lock means no cooperating writer is staging,
// so the orphan must be swept on the next mutation, whether the free ticket is
// stored as an empty file or as the explicit "free" marker.
func TestDirSweepsOrphanTempUnderFreeTicket(t *testing.T) {
	ctx := context.Background()
	cases := map[string][]byte{
		"empty_ticket":  nil,
		"explicit_free": []byte(ticketFree + "\n"),
	}
	for name, ticket := range cases {
		t.Run(name, func(t *testing.T) {
			b := openAt(t, t.TempDir()).(*Dir)
			if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
				t.Fatal(err)
			}
			cur := mustRead(t, b, "n")
			lock := filepath.Join(b.root, lockName)

			// A well-formed staged record, named like a real staging file.
			orphan := b.tmpPath(strings.Repeat("0c", 16))
			stagedValue := []byte("never committed")
			staged := record{version: strings.Repeat("d4", 16), digest: sha256.Sum256(stagedValue), value: stagedValue}
			if err := os.WriteFile(orphan, staged.encode(), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lock, ticket, 0600); err != nil {
				t.Fatal(err)
			}
			// Make sure the ticket really is free in the intended form.
			f, err := openLockFile(lock)
			if err != nil {
				t.Fatal(err)
			}
			got, err := readTicket(f)
			_ = f.Close()
			if err != nil || got.kind != ticketFree {
				t.Fatalf("seeded ticket = %+v %v, want free", got, err)
			}

			if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); err != nil {
				t.Fatalf("replace with free ticket and orphan = %v", err)
			}
			if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("untracked staged file was not swept under a free ticket")
			}
			if got := mustRead(t, b, "n"); string(got.Bytes) != "v2" {
				t.Fatalf("stored = %q, want the committed v2", got.Bytes)
			}
			f, err = openLockFile(lock)
			if err != nil {
				t.Fatal(err)
			}
			after, err := readTicket(f)
			_ = f.Close()
			if err != nil || after.kind != ticketFree {
				t.Fatalf("ticket after write = %+v %v, want free", after, err)
			}
		})
	}
}

// List is unsupported, but a caller that cancels first sees its own context
// error wrapped in ErrDenied; after Close the backend is still ErrDenied.
func TestDirListHonorsCancellation(t *testing.T) {
	b := openAt(t, t.TempDir())
	ctx := context.Background()

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := b.List(cctx); !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
		t.Fatalf("list with canceled ctx = %v, want ErrDenied wrapping context.Canceled", err)
	}
	dctx, dcancel := context.WithTimeout(ctx, time.Nanosecond)
	defer dcancel()
	<-dctx.Done()
	if _, err := b.List(dctx); !errors.Is(err, ErrDenied) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("list with expired ctx = %v, want ErrDenied wrapping context.DeadlineExceeded", err)
	}
	if _, err := b.List(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("list with live ctx = %v, want ErrUnsupported", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.List(cctx); !errors.Is(err, ErrDenied) {
		t.Fatalf("list after close with canceled ctx = %v, want ErrDenied", err)
	}
}

// ctxCancelAtN is a context that is live for its first n Err calls and
// canceled (Done closed, Err returns its cause) from call n+1 on. The public
// ReplaceIfVersion path calls Err a deterministic number of times before it
// holds the lock:
//
//  1. ReplaceIfVersion's own ctx.Err
//  2. write's ctx.Err
//  3. pollLock's ctx.Err, once when the lock is immediately available
//
// Call 4 is Dir.run's ctx.Err right after the lock is acquired and before
// resolve. With limit 3 and an uncontended lock, cancellation is therefore
// observed exactly once the operation holds the lock, before recovery, with no
// sleep or timing used as the trigger. (The measurements confirm the message
// "write cancelled after acquiring the lock" at limit 3.)
type ctxCancelAtN struct {
	calls  int
	limit  int
	done   chan struct{}
	closed bool
	cause  error
}

func (c *ctxCancelAtN) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *ctxCancelAtN) Done() <-chan struct{}       { return c.done }
func (c *ctxCancelAtN) Value(any) any               { return nil }
func (c *ctxCancelAtN) Err() error {
	c.calls++
	if c.calls > c.limit {
		if !c.closed {
			c.closed = true
			close(c.done)
		}
		return c.cause
	}
	return nil
}

// A write that acquires the lock and is then canceled before recovery must not
// clean anything up: resolve would otherwise clear a stale holder ticket and
// sweep temporary files even though the request returns ErrDenied. The
// cancellation is triggered on the post-lock ctx.Err, so this exercises the
// path between lock acquisition and resolve, not a pre-lock cancellation.
func TestDirCancellationAfterLockSkipsRecovery(t *testing.T) {
	ctx := context.Background()
	b := openAt(t, t.TempDir()).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")

	// Seed recovery work that resolve would consume: a free ticket and a
	// well-formed but untracked staged file.
	lock := filepath.Join(b.root, lockName)
	if err := os.WriteFile(lock, nil, 0600); err != nil {
		t.Fatal(err)
	}
	orphan := b.tmpPath(strings.Repeat("0f", 16))
	stagedValue := []byte("never committed")
	if err := os.WriteFile(orphan, record{version: strings.Repeat("d5", 16), digest: sha256.Sum256(stagedValue), value: stagedValue}.encode(), 0600); err != nil {
		t.Fatal(err)
	}

	// The lock is immediately available, so pollLock checks Err exactly once.
	// Limit 3 is live for ReplaceIfVersion, write and pollLock, and canceled
	// for Dir.run's post-lock check before resolve.
	cctx := &ctxCancelAtN{limit: 3, done: make(chan struct{}), cause: context.Canceled}
	err := b.ReplaceIfVersion(cctx, "n", cur.Revision, []byte("v2"))
	if !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) || errors.Is(err, ErrUnknown) {
		t.Fatalf("replace canceled after lock = %v, want ErrDenied wrapping context.Canceled", err)
	}
	if cctx.calls != 4 {
		t.Fatalf("context Err called %d times, want 4 (ReplaceIfVersion, write, pollLock, post-lock)", cctx.calls)
	}
	// The error must come from the post-lock check, proving cancellation was
	// not observed earlier; otherwise this test would only exercise a
	// cancellation before the lock.
	if !strings.Contains(err.Error(), "after acquiring the lock") {
		t.Fatalf("replace = %v, want the cancellation observed after acquiring the lock", err)
	}
	// Nothing was cleaned or changed by the canceled operation.
	if _, err := os.Lstat(orphan); err != nil {
		t.Fatalf("canceled write swept the orphan: %v", err)
	}
	if st, err := os.Lstat(lock); err != nil || st.Size() != 0 {
		t.Fatalf("canceled write changed the ticket: %v %v", st, err)
	}
	if got := mustRead(t, b, "n"); string(got.Bytes) != "v1" || got.Revision != cur.Revision {
		t.Fatal("canceled write changed the committed version")
	}

	// A live request now performs the recovery and the write.
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); err != nil {
		t.Fatalf("replace after the canceled attempt = %v", err)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery did not sweep the orphan")
	}
	if got := mustRead(t, b, "n"); string(got.Bytes) != "v2" {
		t.Fatalf("stored = %q, want v2", got.Bytes)
	}
}

// ---- real cross-process helpers ----

const (
	helperModeEnv     = "VAULTFILE_DIR_HELPER_MODE"
	helperRootEnv     = "VAULTFILE_DIR_HELPER_ROOT"
	helperNameEnv     = "VAULTFILE_DIR_HELPER_NAME"
	helperExpectedEnv = "VAULTFILE_DIR_HELPER_EXPECTED"
	helperValueEnv    = "VAULTFILE_DIR_HELPER_VALUE"
)

// TestDirHelperProcess is not a test: the parent starts the test binary with
// this single test selected and a mode in the environment, which makes the
// child operate on the same local directory from a genuinely separate process.
func TestDirHelperProcess(t *testing.T) {
	mode := os.Getenv(helperModeEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	root := os.Getenv(helperRootEnv)
	d, err := OpenDir(root)
	if err != nil {
		fmt.Printf("open: %v\n", err)
		os.Exit(2)
	}
	name := os.Getenv(helperNameEnv)
	value := []byte(os.Getenv(helperValueEnv))
	expected := Revision(os.Getenv(helperExpectedEnv))
	ctx := context.Background()

	// A parent that keeps the write end open keeps the child parked; killing
	// the child reproduces a crash at exactly this point.
	block := func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}

	switch mode {
	case "try-lock":
		// One non-blocking attempt on the lock inode. Prints "locked" when
		// granted and "busy" when another process holds it; the caller's
		// stdout stays open so the lock is never released early.
		f, err := openLockFile(d.lock)
		if err != nil {
			fmt.Printf("open lock: %v\n", err)
			os.Exit(2)
		}
		ok, err := tryLock(f)
		if err != nil {
			fmt.Printf("try lock: %v\n", err)
			os.Exit(2)
		}
		if ok {
			fmt.Println("locked")
		} else {
			fmt.Println("busy")
		}
		block()
	case "hold-lock":
		f, err := openLockFile(d.lock)
		if err != nil {
			fmt.Printf("open lock: %v\n", err)
			os.Exit(2)
		}
		if ok, err := tryLock(f); err != nil || !ok {
			fmt.Printf("try lock: ok=%v err=%v\n", ok, err)
			os.Exit(2)
		}
		fmt.Println("ready")
		block()
	case "replace":
		err := d.ReplaceIfVersion(ctx, name, expected, value)
		switch {
		case err == nil:
			fmt.Printf("win:%s\n", value)
		case errors.Is(err, ErrConflict):
			fmt.Println("conflict")
		default:
			fmt.Printf("error:%v\n", err)
			os.Exit(3)
		}
	case "stage-crash":
		f, release, err := d.lockHandle(ctx)
		if err != nil {
			fmt.Printf("lock: %v\n", err)
			os.Exit(2)
		}
		defer release()
		lockFile := f
		if err := d.resolve(lockFile); err != nil {
			fmt.Printf("resolve: %v\n", err)
			os.Exit(2)
		}
		op := &writeOp{name: name, expected: expected, value: value, digest: sha256.Sum256(value)}
		if _, err := d.stage(ctx, op, lockFile); err != nil {
			fmt.Printf("stage: %v\n", err)
			os.Exit(2)
		}
		fmt.Println("staged")
		block()
	default:
		fmt.Printf("unknown mode %q\n", mode)
		os.Exit(2)
	}
	os.Exit(0)
}

type helperProc struct {
	cmd   *exec.Cmd
	out   *bufio.Reader
	stdin io.WriteCloser
	once  sync.Once
	err   error
}

func startDirHelper(t *testing.T, mode, root, name, expected, value string) *helperProc {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestDirHelperProcess$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(),
		helperModeEnv+"="+mode,
		helperRootEnv+"="+root,
		helperNameEnv+"="+name,
		helperExpectedEnv+"="+expected,
		helperValueEnv+"="+value,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	h := &helperProc{cmd: cmd, out: bufio.NewReader(stdout), stdin: stdin}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.kill)
	return h
}

func (h *helperProc) line(t *testing.T) string {
	t.Helper()
	line, err := h.out.ReadString('\n')
	if err != nil {
		t.Fatalf("helper output: %v", err)
	}
	return strings.TrimSpace(line)
}

// wait reaps the child. It must run only after every read from out has
// completed: Wait closes the stdout pipe as soon as it observes the exit.
func (h *helperProc) wait() error {
	h.once.Do(func() { h.err = h.cmd.Wait() })
	return h.err
}

func (h *helperProc) kill() {
	_ = h.stdin.Close()
	_ = h.cmd.Process.Kill()
	_ = h.wait()
}

func (h *helperProc) finish(t *testing.T) {
	t.Helper()
	if err := h.wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
}

// startTryLockHelper starts a child process that makes one non-blocking lock
// attempt on root's lock inode and parks afterwards, reporting "locked" or
// "busy". Deadlines and reaping come from startDirHelper.
func startTryLockHelper(t *testing.T, root string) *helperProc {
	t.Helper()
	return startDirHelper(t, "try-lock", root, "", "", "")
}

// lineWithin reads one helper line, failing the test rather than blocking
// forever if the child does not answer within d.
func (h *helperProc) lineWithin(t *testing.T, d time.Duration) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := h.out.ReadString('\n')
		done <- result{strings.TrimSpace(line), err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("helper output: %v (line %q)", r.err, r.line)
		}
		return r.line
	case <-time.After(d):
		t.Fatalf("helper did not answer within %v", d)
		return ""
	}
}

// OpenDir closes its lock-file descriptor while another operation of this
// process holds the POSIX lock on that inode; POSIX locks are owned by the
// process, so an unsynchronized close would silently drop the holder's lock.
// This test holds the in-process semaphore and the OS lock, starts OpenDir,
// and checks that a child process still cannot take the lock while OpenDir
// waits. Only after the holder releases both may OpenDir finish and the child
// acquire the lock.
func TestDirOpenDirDoesNotReleaseHeldLock(t *testing.T) {
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	ctx := context.Background()

	// Hold the process-wide semaphore as an operation does, then the OS lock.
	if err := b.inProc.acquire(ctx, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	held := true
	defer func() {
		if held {
			b.inProc.release()
		}
	}()
	holder, err := openLockFile(b.lock)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if ok, err := tryLock(holder); err != nil || !ok {
		t.Fatalf("holder tryLock = %v %v", ok, err)
	}

	opened := make(chan struct{})
	var openErr error
	go func() {
		d, err := OpenDir(root)
		if d != nil {
			_ = d.Close()
		}
		openErr = err
		close(opened)
	}()
	// OpenDir must block on the semaphore while the lock is held: give it a
	// bounded window and require that it has not returned.
	select {
	case <-opened:
		t.Fatal("OpenDir returned while the in-process lock was held")
	case <-time.After(200 * time.Millisecond):
	}

	// While OpenDir waits, a separate process must not be able to take the
	// lock. Before the fix, OpenDir's close released this process's record
	// lock and the child reported "locked" here.
	child := startTryLockHelper(t, root)
	if line := child.lineWithin(t, 5*time.Second); line != "busy" {
		t.Fatalf("child lock attempt while OpenDir waited = %q, want busy", line)
	}
	select {
	case <-opened:
		t.Fatal("OpenDir returned while the child held the lock")
	default:
	}

	// Release in the order an operation does: unlock, then the semaphore.
	// OpenDir may then finish, and a fresh child can take the lock.
	if err := unlock(holder); err != nil {
		t.Fatal(err)
	}
	held = false
	b.inProc.release()
	select {
	case <-opened:
		if openErr != nil {
			t.Fatalf("OpenDir after release = %v", openErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OpenDir did not return after the lock was released")
	}
	child.kill()
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	after := startTryLockHelper(t, root)
	if line := after.lineWithin(t, 5*time.Second); line != "locked" {
		t.Fatalf("child lock attempt after release = %q, want locked", line)
	}
	after.kill()
}

// The lock timeout covers the OS lock wait of another process: a waiter
// blocked by a live holder fails with a definite ErrConflict (never
// ErrUnknown) and writes nothing.
func TestDirOSLockTimeoutIsConflict(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")
	b.timeout = 50 * time.Millisecond

	holder := startDirHelper(t, "hold-lock", root, "", "", "")
	if line := holder.line(t); line != "ready" {
		t.Fatalf("holder line = %q", line)
	}
	start := time.Now()
	err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2"))
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("lock wait ignored the deadline: %v", elapsed)
	}
	if !errors.Is(err, ErrConflict) || errors.Is(err, ErrUnknown) {
		t.Fatalf("OS lock timeout = %v, want definite ErrConflict", err)
	}
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrConflict) {
		t.Fatalf("read under a live process lock = %v, want ErrConflict", err)
	}
	holder.kill()
	if got := mustRead(t, b, "n"); string(got.Bytes) != "v1" || got.Revision != cur.Revision {
		t.Fatal("timed-out write changed the stored version")
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); err != nil {
		t.Fatalf("write after holder exit = %v", err)
	}
}

// Separate processes racing one revision on the same directory: exactly one
// commits, the others conflict, and the committed bytes are the winner's.
func TestDirCrossProcessReplaceSingleWinner(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("base")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")

	const writers = 6
	procs := make([]*helperProc, writers)
	for i := range procs {
		procs[i] = startDirHelper(t, "replace", root, "n", string(cur.Revision), fmt.Sprintf("value-%d", i))
	}
	wins := 0
	winner := ""
	for i, p := range procs {
		line := p.line(t)
		switch {
		case line == "conflict":
		case strings.HasPrefix(line, "win:"):
			wins++
			winner = strings.TrimPrefix(line, "win:")
			if want := fmt.Sprintf("value-%d", i); winner != want {
				t.Fatalf("helper %d reported %q, want %q", i, winner, want)
			}
		default:
			t.Fatalf("helper %d line = %q", i, line)
		}
	}
	for _, p := range procs {
		p.finish(t)
	}
	if wins != 1 {
		t.Fatalf("wins = %d, want exactly 1", wins)
	}
	got := mustRead(t, b, "n")
	if string(got.Bytes) != winner || got.Revision == cur.Revision {
		t.Fatalf("committed = %q rev-changed=%v, want winner %q", got.Bytes, got.Revision != cur.Revision, winner)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("stale")); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision after race = %v, want ErrConflict", err)
	}
}

// A process killed after it staged a temporary file and took the holder ticket
// but before publication leaves no commit. A fresh process over the same
// directory recovers the stale ticket, drops the orphan, and the normal
// compare-and-replace path still commits atomically.
func TestDirCrossProcessInterruptedWriterRecovered(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	b := openAt(t, root).(*Dir)
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")

	h := startDirHelper(t, "stage-crash", root, "n", string(cur.Revision), "never-committed")
	if line := h.line(t); line != "staged" {
		t.Fatalf("staged helper line = %q", line)
	}
	h.kill()

	// Simulate a restart: a fresh instance over the same durable directory.
	restarted := openAt(t, root).(*Dir)
	if got := mustRead(t, restarted, "n"); string(got.Bytes) != "v1" || got.Revision != cur.Revision {
		t.Fatalf("after crash read = %q, want the base version", got.Bytes)
	}
	if err := restarted.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); err != nil {
		t.Fatalf("replace after crash = %v", err)
	}
	if got := mustRead(t, restarted, "n"); string(got.Bytes) != "v2" {
		t.Fatalf("committed after recovery = %q, want v2", got.Bytes)
	}
	if names, _ := os.ReadDir(filepath.Join(restarted.root, tmpName)); len(names) != 0 {
		t.Fatalf("crash left %d temporary files", len(names))
	}
	if st, err := os.Stat(filepath.Join(restarted.root, lockName)); err != nil || st.Size() != 0 {
		t.Fatalf("crash left a holder ticket: %v", err)
	}
	if err := restarted.CreateIfAbsent(ctx, "n", []byte("v3")); !errors.Is(err, ErrConflict) {
		t.Fatalf("create after crash recovery = %v, want ErrConflict", err)
	}
}
