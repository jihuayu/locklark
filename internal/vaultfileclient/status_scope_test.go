package vaultfileclient

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStatusPathRootComponents(t *testing.T) {
	tests := []struct {
		path, volume, separator, root string
		components                    []string
	}{
		{path: "/one/two", separator: "/", root: "/", components: []string{"one", "two"}},
		{path: `C:\one\two`, volume: "C:", separator: `\`, root: `C:\`, components: []string{"one", "two"}},
		{path: `\\server\share\one`, volume: `\\server\share`, separator: `\`, root: `\\server\share\`, components: []string{"one"}},
	}
	for _, tt := range tests {
		root, components := statusPathRootComponents(tt.path, tt.volume, tt.separator)
		if root != tt.root || !reflect.DeepEqual(components, tt.components) {
			t.Fatalf("STATUS_SCOPE_ROOT_COMPONENTS_FAILED: %q", tt.path)
		}
	}
}

func TestSeparateStatusStatePreservesNamespaceAndMissingRootBoundary(t *testing.T) {
	root := t.TempDir()
	namespace := filepath.Join(root, "vaultfile-backend")
	if os.Mkdir(namespace, 0700) != nil {
		t.Fatal("STATUS_SCOPE_NAMESPACE_FIXTURE_FAILED")
	}
	if err := SeparateStatusState(root, filepath.Join(root, "safe.json")); err != nil {
		t.Fatal("STATUS_SCOPE_SAFE_PATH_REJECTED")
	}
	if err := SeparateStatusState(root, filepath.Join(namespace, "pending.json")); err != ErrConfig {
		t.Fatal("STATUS_SCOPE_NAMESPACE_PATH_ACCEPTED")
	}
	alias := filepath.Join(root, "alias")
	if os.Symlink(namespace, alias) != nil {
		t.Fatal("STATUS_SCOPE_ALIAS_FIXTURE_FAILED")
	}
	if err := SeparateStatusState(root, filepath.Join(alias, "pending.json")); err != ErrConfig {
		t.Fatal("STATUS_SCOPE_SYMLINK_ALIAS_ACCEPTED")
	}
	if err := SeparateStatusState(filepath.Join(root, "absent"), filepath.Join(root, "safe.json")); err != nil {
		t.Fatal("STATUS_SCOPE_ABSENT_ROOT_REJECTED")
	}
	dangling := filepath.Join(root, "dangling")
	if os.Symlink(filepath.Join(root, "missing"), dangling) != nil {
		t.Fatal("STATUS_SCOPE_DANGLING_FIXTURE_FAILED")
	}
	if err := SeparateStatusState(dangling, filepath.Join(root, "safe.json")); err != ErrBackend {
		t.Fatal("STATUS_SCOPE_DANGLING_ROOT_ACCEPTED")
	}
}
