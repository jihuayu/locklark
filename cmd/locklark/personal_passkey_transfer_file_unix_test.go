//go:build !windows

package main

// Unix counterpart of the Windows DACL fixture test: prove the private fixture
// class is accepted by the production private reader and the deliberately
// shared class is refused.

import (
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/internal/teamfiles"
)

func TestPasskeyTransferUnixFixtureModes(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "private.json")
	passkeyTransferWritePrivate(t, private, []byte(`{"v":1}`))
	passkeyTransferAssertOwnerPrivate(t, private)
	raw, err := teamfiles.Read(private, maxPasskeyTransferInvitationBytes, true)
	if err != nil || string(raw) != `{"v":1}` {
		t.Fatalf("production private reader refused owner-only fixture: len=%d err=%v", len(raw), err)
	}
	clear(raw)

	shared := filepath.Join(dir, "shared.json")
	passkeyTransferWriteShared(t, shared, []byte(`{"v":1}`))
	if err := passkeyTransferPrivateFileError(shared); err == nil {
		t.Fatal("group-readable fixture accepted as owner-private")
	}
	if raw, err := teamfiles.Read(shared, maxPasskeyTransferInvitationBytes, true); err == nil || raw != nil {
		clear(raw)
		t.Fatalf("production private reader accepted a group-readable file: len=%d err=%v", len(raw), err)
	}
}
