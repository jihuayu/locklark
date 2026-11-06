package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateOracleBoundParentInIsolatedChild(t *testing.T) {
	const helper = "LOCKLARK_TEST_PRIVATE_ORACLE_CHILD"
	if os.Getenv(helper) == "1" {
		if len(os.Args) < 3 || privateRootAt(os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]) != nil {
			t.Fatal("isolated child rejected bound private oracle")
		}
		return
	}
	root, err := newPrivateRoot()
	if err != nil {
		t.Fatal("private oracle root creation failed")
	}
	defer os.RemoveAll(root)
	if privateRoot(root) != nil {
		t.Fatal("OS-known-folder private oracle validation failed")
	}
	parent := filepath.Dir(root)
	for _, name := range []string{"isolated-home", "isolated-config", "isolated-data"} {
		if os.Mkdir(filepath.Join(root, name), 0700) != nil {
			t.Fatal("isolated profile directory creation failed")
		}
	}
	args := cliArgs(root, os.Args[0], "approved", fixture{})
	if len(args) < 4 || args[len(args)-4] != "child" || args[len(args)-3] != root || args[len(args)-2] != parent || args[len(args)-1] != "approved" {
		t.Fatal("approved command did not bind private oracle parent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsPrivateOracleBoundParentInIsolatedChild$", "--", root, parent)
	cmd.WaitDelay = time.Second
	// Match the profile isolation that caused the real acceptance-child failure.
	// Neither the validator nor the child may derive the oracle from this env.
	cmd.Env = []string{helper + "=1", "SYSTEMROOT=" + os.Getenv("SYSTEMROOT"), "PATH=" + os.Getenv("PATH"),
		"USERPROFILE=" + filepath.Join(root, "isolated-home"), "APPDATA=" + filepath.Join(root, "isolated-config"),
		"LOCALAPPDATA=" + filepath.Join(root, "isolated-data"), "TMP=" + root, "TEMP=" + root}
	if cmd.Run() != nil {
		t.Fatal("isolated child private oracle validation failed")
	}
	if privateRoot(root) != nil {
		t.Fatal("parent private oracle validation failed after child")
	}
}

func TestWindowsPrivateOracleRejectsParentAndACLChanges(t *testing.T) {
	root, err := newPrivateRoot()
	if err != nil {
		t.Fatal("private oracle root creation failed")
	}
	defer os.RemoveAll(root)
	parent := filepath.Dir(root)
	if privateRootAt(root, parent) != nil {
		t.Fatal("valid private oracle rejected")
	}
	for _, paths := range [][2]string{{root, filepath.Join(parent, "other-parent")}, {root, "."},
		{"locklark-run-cli-acceptance-relative", parent}, {root + `\.`, parent}, {root, parent + `\.`}} {
		if privateRootAt(paths[0], paths[1]) == nil {
			t.Fatal("non-exact private oracle parent accepted")
		}
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("current user lookup failed")
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;GR;;;WD)")
	if err != nil {
		t.Fatal("negative DACL preparation failed")
	}
	acl, _, err := sd.DACL()
	if err != nil || windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil) != nil {
		t.Fatal("negative DACL installation failed")
	}
	if privateRootAt(root, parent) == nil {
		t.Fatal("foreign-readable private oracle accepted")
	}
}
