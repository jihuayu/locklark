//go:build unix

package teamfiles

import (
	"os"
	"path/filepath"
	"testing"
)

func privateUnixMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal("PRIVATE_TEST_STAT_FAILED")
	}
	return info.Mode().Perm()
}

func TestPrivateUnixParentMaskVersusWorkspaceExact(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name          string
		mode          os.FileMode
		parentAllowed bool
		workspaceOK   bool
	}{
		{"0500", 0500, true, false},
		{"0700", 0700, true, true},
		{"0755", 0755, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(root, tc.name)
			if err := os.Mkdir(path, tc.mode); err != nil {
				t.Fatal("PRIVATE_TEST_MKDIR_FAILED")
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal("PRIVATE_TEST_CHMOD_FAILED")
			}
			if got := ValidatePrivateParent(path) == nil; got != tc.parentAllowed {
				t.Fatalf("PRIVATE_PARENT_POLICY_MISMATCH mode=%s allowed=%t", tc.name, got)
			}
			if got := ValidatePrivateWorkspace(path) == nil; got != tc.workspaceOK {
				t.Fatalf("PRIVATE_WORKSPACE_POLICY_MISMATCH mode=%s allowed=%t", tc.name, got)
			}
			if got := privateUnixMode(t, path); got != tc.mode {
				t.Fatalf("PRIVATE_TEST_MODE_CHANGED mode=%s got=%s", tc.name, got)
			}
		})
	}
}

func TestPrivateUnixFileExact0600(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name    string
		mode    os.FileMode
		allowed bool
	}{
		{"0600", 0600, true},
		{"0644", 0644, false},
		{"0400", 0400, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(root, tc.name)
			if err := os.WriteFile(path, []byte("synthetic"), tc.mode); err != nil {
				t.Fatal("PRIVATE_TEST_FILE_FAILED")
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal("PRIVATE_TEST_CHMOD_FAILED")
			}
			if got := ValidatePrivateFile(path) == nil; got != tc.allowed {
				t.Fatalf("PRIVATE_FILE_POLICY_MISMATCH mode=%s allowed=%t", tc.name, got)
			}
			if got := privateUnixMode(t, path); got != tc.mode {
				t.Fatalf("PRIVATE_TEST_FILE_MODE_CHANGED mode=%s got=%s", tc.name, got)
			}
		})
	}
}

func TestPrivateUnixRejectsSymlinkAndWrongShape(t *testing.T) {
	root := t.TempDir()
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0700); err != nil {
		t.Fatal("PRIVATE_TEST_MKDIR_FAILED")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(privateDir, link); err != nil {
		t.Fatal("PRIVATE_TEST_SYMLINK_FAILED")
	}
	if ValidatePrivateParent(link) == nil || ValidatePrivateWorkspace(link) == nil {
		t.Fatal("PRIVATE_DIRECTORY_SYMLINK_ACCEPTED")
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal("PRIVATE_TEST_FILE_FAILED")
	}
	if ValidatePrivateParent(file) == nil || ValidatePrivateWorkspace(file) == nil {
		t.Fatal("PRIVATE_NON_DIRECTORY_ACCEPTED")
	}
	if ValidatePrivateFile(privateDir) == nil {
		t.Fatal("PRIVATE_NON_REGULAR_FILE_ACCEPTED")
	}
}

func TestPrivateUnixEnsureWorkspace(t *testing.T) {
	root := t.TempDir()

	created := filepath.Join(root, "created")
	if err := EnsurePrivateWorkspace(created); err != nil {
		t.Fatal("PRIVATE_ENSURE_CREATE_FAILED")
	}
	if got := privateUnixMode(t, created); got != 0700 {
		t.Fatalf("PRIVATE_ENSURE_CREATE_MODE_WRONG got=%s", got)
	}
	if EnsurePrivateWorkspace(created) != nil {
		t.Fatal("PRIVATE_ENSURE_IDEMPOTENT_FAILED")
	}
	if got := privateUnixMode(t, created); got != 0700 {
		t.Fatalf("PRIVATE_ENSURE_IDEMPOTENT_CHANGED_MODE got=%s", got)
	}

	loose := filepath.Join(root, "loose")
	if err := os.Mkdir(loose, 0755); err != nil {
		t.Fatal("PRIVATE_TEST_MKDIR_FAILED")
	}
	if err := os.Chmod(loose, 0755); err != nil {
		t.Fatal("PRIVATE_TEST_CHMOD_FAILED")
	}
	if EnsurePrivateWorkspace(loose) == nil {
		t.Fatal("PRIVATE_ENSURE_ACCEPTED_EXISTING_0755")
	}
	if got := privateUnixMode(t, loose); got != 0755 {
		t.Fatalf("PRIVATE_ENSURE_CHANGED_EXISTING_MODE got=%s", got)
	}

	readOnlyParent := filepath.Join(root, "read-only-parent")
	if err := os.Mkdir(readOnlyParent, 0755); err != nil {
		t.Fatal("PRIVATE_TEST_MKDIR_FAILED")
	}
	if err := os.Chmod(readOnlyParent, 0755); err != nil {
		t.Fatal("PRIVATE_TEST_CHMOD_FAILED")
	}
	underReadOnly := filepath.Join(readOnlyParent, "workspace")
	if err := EnsurePrivateWorkspace(underReadOnly); err != nil {
		t.Fatal("PRIVATE_ENSURE_REJECTED_READABLE_PARENT")
	}
	if got := privateUnixMode(t, underReadOnly); got != 0700 {
		t.Fatalf("PRIVATE_ENSURE_CREATE_MODE_WRONG got=%s", got)
	}

	writableParent := filepath.Join(root, "writable-parent")
	if err := os.Mkdir(writableParent, 0775); err != nil {
		t.Fatal("PRIVATE_TEST_MKDIR_FAILED")
	}
	if err := os.Chmod(writableParent, 0775); err != nil {
		t.Fatal("PRIVATE_TEST_CHMOD_FAILED")
	}
	notCreated := filepath.Join(writableParent, "workspace")
	if EnsurePrivateWorkspace(notCreated) == nil {
		t.Fatal("PRIVATE_ENSURE_ACCEPTED_WRITABLE_PARENT")
	}
	if _, err := os.Lstat(notCreated); !os.IsNotExist(err) {
		t.Fatal("PRIVATE_ENSURE_CREATED_UNDER_WRITABLE_PARENT")
	}
}

func TestPrivateUnixEnsureRejectsSymlinkLeaf(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal("PRIVATE_TEST_MKDIR_FAILED")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal("PRIVATE_TEST_SYMLINK_FAILED")
	}
	if EnsurePrivateWorkspace(link) == nil {
		t.Fatal("PRIVATE_ENSURE_ACCEPTED_SYMLINK_LEAF")
	}
	if got := privateUnixMode(t, target); got != 0700 {
		t.Fatalf("PRIVATE_ENSURE_CHANGED_SYMLINK_TARGET got=%s", got)
	}
}
