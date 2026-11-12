package vaultfilesync

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// newFixtureBackend returns an in-process Memory backend. The local directory
// backend is unsupported on Windows, so Memory serves only as this package's
// test remote; it makes no claim of local directory support.
func newFixtureBackend(t *testing.T) vaultfilebackend.Backend {
	t.Helper()
	return vaultfilebackend.NewMemory()
}

// winDirectoryRights is FILE_ALL_ACCESS as the production directory DACL
// grants it. Traverse is allowed so cleanup can descend into the directory.
const winDirectoryRights = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff

// newJournalDir returns a fresh empty directory below the test's temp root
// carrying a protected DACL that matches vaultfilejournal's private file
// security: full control to this process user, LocalSystem and Administrators
// only. Any step that cannot be applied or verified fails the test.
func newJournalDir(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current user identity: %v", err)
	}
	sids := []*windows.SID{user.User.Sid}
	for _, text := range []string{"S-1-5-18", "S-1-5-32-544"} {
		sid, err := windows.StringToSid(text)
		if err != nil || sid == nil {
			t.Fatalf("well-known SID %s: %v", text, err)
		}
		sids = append(sids, sid)
	}
	entries := make([]windows.EXPLICIT_ACCESS, len(sids))
	for i, sid := range sids {
		entries[i] = windows.EXPLICIT_ACCESS{
			AccessPermissions: winDirectoryRights,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("build private DACL: %v", err)
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatalf("new security descriptor: %v", err)
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		t.Fatalf("set private DACL: %v", err)
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		t.Fatalf("protect private DACL: %v", err)
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	var dir string
	for attempt := 0; attempt < 16; attempt++ {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			t.Fatal(err)
		}
		name := "journal-" + hex.EncodeToString(suffix[:])
		candidate := filepath.Join(t.TempDir(), name)
		wide, err := windows.UTF16PtrFromString(candidate)
		if err != nil {
			t.Fatalf("directory name: %v", err)
		}
		switch err := windows.CreateDirectory(wide, &attributes); {
		case errors.Is(err, windows.ERROR_ALREADY_EXISTS), errors.Is(err, windows.ERROR_FILE_EXISTS):
			continue
		case err != nil:
			t.Fatalf("create private directory: %v", err)
		}
		dir = candidate
		break
	}
	if dir == "" {
		t.Fatal("private directory name collision")
	}
	if err := verifyPrivateJournalDir(dir, user.User.Sid, sids); err != nil {
		t.Fatalf("verify private directory: %v", err)
	}
	return dir
}

// verifyPrivateJournalDir reads the directory security back and requires the
// current user as owner, a protected DACL, and only the given principals each
// with the expected rights. Anything else fails closed.
func verifyPrivateJournalDir(dir string, owner *windows.SID, sids []*windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read security: %w", err)
	}
	gotOwner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner: %w", err)
	}
	if gotOwner == nil || owner == nil || !gotOwner.Equals(owner) {
		return fmt.Errorf("owner is not the current process user")
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("read control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("DACL is not protected")
	}
	acl, defaulted, err := sd.DACL()
	if err != nil || defaulted || acl == nil {
		return fmt.Errorf("DACL is absent, defaulted or unreadable: %v", err)
	}
	if int(acl.AceCount) != len(sids) {
		return fmt.Errorf("DACL has %d entries, want %d", acl.AceCount, len(sids))
	}
	// Key by SID value, not by pointer: distinct *windows.SID values can denote
	// the same principal.
	expected := make(map[string]bool, len(sids))
	for _, sid := range sids {
		key, err := privateJournalSIDKey(sid)
		if err != nil {
			return fmt.Errorf("expected principal: %w", err)
		}
		expected[key] = true
	}
	got := make(map[string]bool, len(sids))
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d: %w", i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("ACE %d has type %d, want an allowed entry", i, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		key, err := privateJournalSIDKey(sid)
		if err != nil {
			return fmt.Errorf("ACE %d principal: %w", i, err)
		}
		if !expected[key] {
			return fmt.Errorf("ACE %d grants an untrusted principal %s", i, key)
		}
		if got[key] {
			return fmt.Errorf("ACE %d duplicates %s", i, key)
		}
		got[key] = true
		if uint32(ace.Mask) != winDirectoryRights {
			return fmt.Errorf("ACE %d grants 0x%x to %s, want 0x%x", i, uint32(ace.Mask), key, winDirectoryRights)
		}
	}
	for key := range expected {
		if !got[key] {
			return fmt.Errorf("DACL is missing an allowed entry for %s", key)
		}
	}
	return nil
}

// privateJournalSIDKey returns sid's string form, failing on SIDs that cannot
// be rendered so an unreadable principal is never treated as a match.
func privateJournalSIDKey(sid *windows.SID) (string, error) {
	if sid == nil {
		return "", errors.New("nil SID")
	}
	key := sid.String()
	if key == "" {
		return "", errors.New("SID cannot be rendered")
	}
	return key, nil
}
