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
	"os"
	"os/exec"
	"path/filepath"
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
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	d := openAt(t, root).(*Dir)
	st3, err := os.Stat(d.lock)
	if err != nil || !os.SameFile(st1, st3) {
		t.Fatal("reopen after Close locked a different inode")
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

// assertComponentReplacementDenied moves b's component c aside and puts a real
// directory with valid-looking contents in its place, then requires Read,
// Replace and Create to be denied and nothing under the replacement to change
// or be created.
func assertComponentReplacementDenied(t *testing.T, b *Dir, c replacedComponent) {
	t.Helper()
	ctx := context.Background()
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur := mustRead(t, b, "n")
	orig := c.path(b)
	moved := orig + ".moved"
	if err := os.Rename(orig, moved); err != nil {
		t.Fatal(err)
	}
	// Build the replacement at the same absolute path, so the backend's own
	// paths reach it, with valid-looking contents: a complete v1 layout and a
	// well-formed record carrying the current revision, so a follow-through
	// would let Read return alternate bytes and let Replace commit there.
	// Only the identity differs.
	altValue := []byte("alternate")
	altRecord := record{version: string(cur.Revision), digest: sha256.Sum256(altValue), value: altValue}.encode()
	for _, d := range []string{orig, filepath.Join(orig, dirVer), filepath.Join(orig, dirVer, tmpName), filepath.Join(orig, dirVer, dataName)} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// The record goes where the backend would look for it under the
	// replacement, whatever component was replaced.
	rel, err := filepath.Rel(b.root, b.dataPath("n"))
	if err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(orig, rel)
	if err := os.MkdirAll(filepath.Dir(entry), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, altRecord, 0600); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Lstat(orig); err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 {
		t.Fatalf("replacement is not a real 0700 directory: %v %v", st, err)
	}
	if _, err := b.Read(ctx, "n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("%s replaced by a real directory: read = %v, want ErrDenied", c.name, err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("%s replaced by a real directory: replace = %v, want ErrDenied", c.name, err)
	}
	if err := b.CreateIfAbsent(ctx, "fresh", []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("%s replaced by a real directory: create = %v, want ErrDenied", c.name, err)
	}
	// Exactly the seed record is present: no other data file, no temporary
	// file and no lock file was created under the replacement.
	if got, err := os.ReadFile(entry); err != nil || !bytes.Equal(got, altRecord) {
		t.Fatalf("%s replaced: alternative record changed: %v", c.name, err)
	}
	var listed []string
	if err := filepath.WalkDir(orig, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			listed = append(listed, p)
		}
		return nil
	}); err != nil {
		t.Fatalf("%s replaced: walk alternative: %v", c.name, err)
	}
	if len(listed) != 1 || listed[0] != entry {
		t.Fatalf("%s replaced: alternative tree gained files: %v", c.name, listed)
	}
	// Restoring the original tree restores service and the committed version.
	if err := os.RemoveAll(orig); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, orig); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, b, "n"); string(got.Bytes) != "v1" || got.Revision != cur.Revision {
		t.Fatal("restored component does not serve the committed version")
	}
}

// Every protected component replaced after OpenDir by another real directory
// with acceptable mode, owner and valid-looking contents is refused: the
// inode identity captured by OpenDir no longer matches, so the existing
// backend never silently switches to the alternative tree. For the root and
// v1 the replacement lacks the subdirectories below them, so the operation is
// also refused by the component checks; for ns, tmp and data the replacement
// is fully valid and only the identity check stands between it and the store.
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
