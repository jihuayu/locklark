//go:build windows

package main

// The transfer fixture helpers must produce the native Windows privacy classes
// the CLI really checks. A mode bit cannot express either class here, so this
// test drives the production private reader against a genuine owner-protected
// DACL and against a genuine Everyone read ACE.

import (
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/internal/teamfiles"
)

func TestPasskeyTransferWindowsFixtureUsesNativePrivateDACL(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "private.json")
	passkeyTransferWritePrivate(t, private, []byte(`{"v":1}`))
	if err := passkeyTransferPrivateFileError(private); err != nil {
		t.Fatalf("owner-only fixture rejected: %v", err)
	}
	raw, err := teamfiles.Read(private, maxPasskeyTransferInvitationBytes, true)
	if err != nil || string(raw) != `{"v":1}` {
		t.Fatalf("production private reader refused owner-only fixture: len=%d err=%v", len(raw), err)
	}
	clear(raw)

	// The negative installs a real Everyone read ACE; the same production
	// reader must refuse it. os.Chmod(0644) would prove nothing on Windows.
	shared := filepath.Join(dir, "shared.json")
	passkeyTransferWriteShared(t, shared, []byte(`{"v":1}`))
	if err := passkeyTransferPrivateFileError(shared); err == nil {
		t.Fatal("Everyone-readable fixture accepted as owner-private")
	}
	if raw, err := teamfiles.Read(shared, maxPasskeyTransferInvitationBytes, true); err == nil || raw != nil {
		clear(raw)
		t.Fatalf("production private reader accepted an Everyone read ACE: len=%d err=%v", len(raw), err)
	}

	// Recreating the same path restores the owner-protected ACL, so a negative
	// fixture can never leak into a later positive assertion.
	passkeyTransferWritePrivate(t, shared, []byte(`{"v":2}`))
	passkeyTransferAssertOwnerPrivate(t, shared)
}
