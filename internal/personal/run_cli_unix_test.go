//go:build !windows

package personal

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCLIRefusesReplaceableTemporaryParents(t *testing.T) {
	base := t.TempDir()
	unsafeParent := filepath.Join(base, "public")
	privateLeaf := filepath.Join(unsafeParent, "private")
	if os.Mkdir(unsafeParent, 0700) != nil || os.Mkdir(privateLeaf, 0700) != nil || os.Chmod(unsafeParent, 0777) != nil {
		t.Fatal("permission fixture unavailable")
	}
	info, e := os.Lstat(unsafeParent)
	if e != nil || info.Mode().Perm()&0022 == 0 || info.Mode()&os.ModeSticky != 0 {
		t.Fatal("fixture does not expose the directory replacement risk")
	}
	request := cliRequest(t)
	target := RevealTarget{ID: strings.Repeat("1", 32), Revision: strings.Repeat("a", 64), Field: "password"}
	for _, parent := range []string{unsafeParent, privateLeaf} {
		t.Run("untrusted-chain", func(t *testing.T) {
			t.Setenv("TMPDIR", parent)
			prepared, executed := 0, 0
			_, e := runCLI(context.Background(), target, request, func(*RunRequest) (result, error) {
				prepared++
				return result{value: []byte("private-cli-value")}, nil
			}, func(context.Context, RunRequest, []byte) (int, error) {
				executed++
				return 0, nil
			}, os.RemoveAll)
			if e != ErrRunTemporary || prepared != 0 || executed != 0 {
				t.Fatal("replaceable temporary ancestry reached intent or process execution")
			}
		})
	}
}

func TestRunCLIUsesCanonicalPrivateTemporaryParent(t *testing.T) {
	parent := t.TempDir()
	canonical, e := filepath.EvalSymlinks(parent)
	if e != nil {
		t.Fatal("private parent unavailable")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if os.Symlink(parent, alias) != nil {
		t.Fatal("parent alias fixture unavailable")
	}
	request := cliRequest(t)
	target := RevealTarget{ID: strings.Repeat("1", 32), Revision: strings.Repeat("a", 64), Field: "password"}
	t.Setenv("TMPDIR", alias)
	root := ""
	_, e = runCLI(context.Background(), target, request, func(r *RunRequest) (result, error) {
		root = r.cli.root
		info, e := os.Stat(root)
		if e != nil || info.Mode().Perm() != 0700 {
			t.Fatal("temporary root not private")
		}
		return result{value: []byte("private-cli-value")}, nil
	}, func(context.Context, RunRequest, []byte) (int, error) { return 0, nil }, os.RemoveAll)
	if e != nil || filepath.Dir(root) != canonical {
		t.Fatal("execution did not use the validated canonical parent")
	}
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("canonical temporary root survived execution")
	}
}
