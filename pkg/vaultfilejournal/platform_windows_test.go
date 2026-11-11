//go:build windows

package vaultfilejournal

import (
	"testing"

	"golang.org/x/sys/windows"
)

// makeParentShared grants an untrusted principal traversal, list and write
// rights on the directory. The journal must reject it and must not restore or
// otherwise alter the DACL.
func makeParentShared(t *testing.T, dir string) {
	t.Helper()
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	setListAndWriteACE(t, dir, everyone)
}

// makeDBPrivate rewrites an existing file's DACL to exactly what the journal
// publishes: a protected DACL granting full control only to the current user.
func makeDBPrivate(t *testing.T, path string) {
	t.Helper()
	sd, err := privateFileSecurity()
	if err != nil {
		t.Fatal(err)
	}
	mustSetDACL(t, path, sd)
}

// mustLinkDir creates a directory symbolic link (a reparse point).
func mustLinkDir(t *testing.T, target, link string) {
	t.Helper()
	if err := createDirSymlink(link, target); err != nil {
		t.Fatal(err)
	}
}

// mustLinkFile creates a file symbolic link (a reparse point).
func mustLinkFile(t *testing.T, target, link string) {
	t.Helper()
	if err := createFileSymlink(link, target); err != nil {
		t.Fatal(err)
	}
}

// posixModeChecks is false: FileMode.Perm is not ACL evidence on Windows.
const posixModeChecks = false

// checkLocalPermissions requires the database DACL to admit only trusted
// principals and the parent to pass the Windows directory rules.
func checkLocalPermissions(t *testing.T, dbPath, parent string) {
	t.Helper()
	file, _, missing, err := openValidatedDB(dbPath)
	if err != nil || missing {
		t.Fatalf("database is not privately secured: missing=%t err=%v", missing, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if !isDACLProtected(t, dbPath) {
		t.Fatal("database DACL is not protected")
	}
	if err := checkPrivateDir(parent); err != nil {
		t.Fatalf("parent is not private: %v", err)
	}
}
