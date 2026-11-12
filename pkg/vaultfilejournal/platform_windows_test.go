//go:build windows

package vaultfilejournal

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// privateDir returns a fresh empty directory under t.TempDir() carrying a
// protected DACL that matches privateFileSecurity: full control to this
// process user, LocalSystem and Administrators only. The DACL is applied by
// the creation call and then read back; any step that fails fails the test.
func privateDir(t *testing.T) string {
	t.Helper()
	owner, trusted := journalTestPrincipals(t)
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: journalTestDirectorySecurity(t, trusted),
	}
	for attempt := 0; attempt < 16; attempt++ {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "journal-"+hex.EncodeToString(suffix[:]))
		wide, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			t.Fatal(err)
		}
		switch err := windows.CreateDirectory(wide, &attributes); {
		case errors.Is(err, windows.ERROR_ALREADY_EXISTS), errors.Is(err, windows.ERROR_FILE_EXISTS):
			continue
		case err != nil:
			t.Fatalf("create private directory: %v", err)
		}
		if err := verifyJournalTestDirectory(dir, owner, trusted); err != nil {
			t.Fatalf("verify private directory: %v", err)
		}
		return dir
	}
	t.Fatal("private directory name collision")
	return ""
}

// journalTestDirectoryRights is FILE_ALL_ACCESS, the right set the production
// directory DACL is not required to grant but that keeps cleanup possible.
const journalTestDirectoryRights = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff

// journalTestPrincipals returns this process user and LocalSystem,
// Administrators and TrustedInstaller as SIDs.
func journalTestPrincipals(t *testing.T) (*windows.SID, []*windows.SID) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current user identity: %v", err)
	}
	trusted := []*windows.SID{user.User.Sid}
	for _, text := range []string{
		"S-1-5-18",
		"S-1-5-32-544",
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
	} {
		sid, err := windows.StringToSid(text)
		if err != nil || sid == nil {
			t.Fatalf("well-known SID %s: %v", text, err)
		}
		trusted = append(trusted, sid)
	}
	return user.User.Sid, trusted
}

// journalTestDirectorySecurity builds an absolute descriptor granting
// journalTestDirectoryRights to each of trusted and nothing else, with no
// inherited entries.
func journalTestDirectorySecurity(t *testing.T, trusted []*windows.SID) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	entries := make([]windows.EXPLICIT_ACCESS, len(trusted))
	for i, sid := range trusted {
		entries[i] = windows.EXPLICIT_ACCESS{
			AccessPermissions: journalTestDirectoryRights,
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
	return sd
}

// verifyJournalTestDirectory reads dir's security back and requires owner as
// the owner, a SE_DACL_PROTECTED DACL, and exactly one allowed entry for each
// of trusted, each with journalTestDirectoryRights.
func verifyJournalTestDirectory(dir string, owner *windows.SID, trusted []*windows.SID) error {
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
		return errors.New("owner is not the current process user")
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
	if int(acl.AceCount) != len(trusted) {
		return fmt.Errorf("DACL has %d entries, want %d", acl.AceCount, len(trusted))
	}
	// Key by SID value, not by pointer: distinct *windows.SID values can denote
	// the same principal.
	expected := make(map[string]bool, len(trusted))
	for _, sid := range trusted {
		key, err := journalTestSIDKey(sid)
		if err != nil {
			return fmt.Errorf("expected principal: %w", err)
		}
		expected[key] = true
	}
	got := make(map[string]bool, len(trusted))
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d: %w", i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("ACE %d has type %d, want an allowed entry", i, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		key, err := journalTestSIDKey(sid)
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
		if uint32(ace.Mask) != journalTestDirectoryRights {
			return fmt.Errorf("ACE %d grants 0x%x to %s, want 0x%x", i, uint32(ace.Mask), key, journalTestDirectoryRights)
		}
	}
	for key := range expected {
		if !got[key] {
			return fmt.Errorf("DACL is missing an allowed entry for %s", key)
		}
	}
	return nil
}

// journalTestSIDKey returns sid's string form, failing on SIDs that cannot be
// rendered so an unreadable principal is never treated as a match.
func journalTestSIDKey(sid *windows.SID) (string, error) {
	if sid == nil {
		return "", errors.New("nil SID")
	}
	key := sid.String()
	if key == "" {
		return "", errors.New("SID cannot be rendered")
	}
	return key, nil
}

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
