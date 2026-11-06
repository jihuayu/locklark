//go:build unix

package teamclient

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestBootstrapPrivateProfileFilesRejectAliasesAndPermissions(t *testing.T) {
	for _, mode := range []string{"readable", "symlink", "hardlink", "missing-lease", "lease-permissions", "writable-parent"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "service")
			p, e := PrepareSequencer(path)
			if e != nil {
				t.Fatal("prepare")
			}
			defer p.Close()
			switch mode {
			case "readable":
				if os.Chmod(path, 0644) != nil {
					t.Fatal("chmod")
				}
			case "symlink":
				if os.Rename(path, path+".real") != nil || os.Symlink(path+".real", path) != nil {
					t.Fatal("symlink")
				}
			case "hardlink":
				if os.Link(path, path+".alias") != nil {
					t.Fatal("hardlink")
				}
			case "missing-lease":
				if os.Remove(path+".identity-lease") != nil {
					t.Fatal("remove lease fixture")
				}
			case "lease-permissions":
				if os.Chmod(path+".identity-lease", 0660) != nil {
					t.Fatal("chmod lease")
				}
			case "writable-parent":
				if os.Chmod(root, 0777) != nil {
					t.Fatal("chmod parent")
				}
				defer os.Chmod(root, 0700)
			}
			if _, e := ReadBootstrapStatus(path); e != ErrProfile {
				t.Fatal("untrusted profile path accepted")
			}
		})
	}
}

func TestBootstrapIdentityLeaseSurvivesPublicDBInodeReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service")
	p, e := PrepareSequencer(path)
	if e != nil {
		t.Fatal("prepare")
	}
	defer p.Close()
	backup, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("public backup")
	}
	lease, e := openProfile(path)
	if e != nil {
		t.Fatal("lease")
	}
	defer lease.close()
	if os.Rename(path, path+".old") != nil || os.WriteFile(path, backup, 0600) != nil {
		t.Fatal("replace public DB inode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBootstrapIdentityLeaseChild$")
	cmd.Env = append(os.Environ(), "LOCKLARK_TEST_PROFILE_LEASE="+path)
	if out, e := cmd.CombinedOutput(); e != nil || string(out) != "PASS\n" {
		t.Fatal("replaced DB inode bypassed fixed identity lease")
	}
}
