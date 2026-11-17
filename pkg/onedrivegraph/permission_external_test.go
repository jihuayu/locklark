package onedrivegraph_test

import (
	"testing"

	"github.com/jihuayu/locklark/pkg/onedrivegraph"
)

// Callers outside the package must be able to use the documented fixed roles
// directly, without converting raw strings to PermissionRole.
func TestPermissionRoleConstantsAreExported(t *testing.T) {
	var read onedrivegraph.PermissionRole = onedrivegraph.PermissionRoleRead
	var write onedrivegraph.PermissionRole = onedrivegraph.PermissionRoleWrite
	if read != "read" {
		t.Errorf("PermissionRoleRead = %q, want %q", read, "read")
	}
	if write != "write" {
		t.Errorf("PermissionRoleWrite = %q, want %q", write, "write")
	}
}
