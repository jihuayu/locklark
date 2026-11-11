//go:build windows

package vaultfilejournal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// resetDACL builds a self-relative descriptor with a protected DACL holding
// exactly the given explicit allow entries. It is only used to build hostile
// fixtures; evaluation happens in the package's own DACL walkers.
func resetDACL(entries []windows.EXPLICIT_ACCESS) (*windows.SECURITY_DESCRIPTOR, error) {
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return nil, err
	}
	absolute, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := absolute.SetDACL(acl, true, false); err != nil {
		return nil, err
	}
	return absolute.ToSelfRelative()
}

// mustSetDACL replaces path's DACL with sd's, marking it protected so no
// entry is inherited afterwards.
func mustSetDACL(t *testing.T, path string, sd *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("fixture DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

// sidRule builds an explicit allow entry for sid with mask.
func sidRule(sid *windows.SID, mask windows.ACCESS_MASK, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

// setListAndWriteACE replaces path's DACL with a protected one granting
// sid list/write rights on the object and, creating a file inside it, the
// directory delete-child right that a scriptless runner needs for cleanup.
// Nothing else is granted.
func setListAndWriteACE(t *testing.T, path string, sid *windows.SID) {
	t.Helper()
	sd, err := resetDACL([]windows.EXPLICIT_ACCESS{sidRule(sid,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|
			deleteChildMask, 0)})
	if err != nil {
		t.Fatal(err)
	}
	mustSetDACL(t, path, sd)
}

// readAllowACEs returns the non-inherit-only allowed ACEs of path.
func readAllowACEs(t *testing.T, path string) []*windows.ACCESS_ALLOWED_ACE {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("DACL: %v", err)
	}
	var out []*windows.ACCESS_ALLOWED_ACE
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceFlags&aceFlagsInheritOnly == 0 {
			out = append(out, ace)
		}
	}
	return out
}

func isDACLProtected(t *testing.T, path string) bool {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	return control&windows.SE_DACL_PROTECTED != 0
}

// TestWindowsOpenPublishesPrivateDatabase covers a normal local
// Open/Save/Close/reopen on Windows and proves the published database has a
// protected DACL granting nothing to untrusted principals.
func TestWindowsOpenPublishesPrivateDatabase(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "journal.db")
	want := baseProposal()

	j, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	mustSave(t, j, want)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), journalTempPrefix) {
			t.Fatalf("publication left a temporary file %q", e.Name())
		}
	}
	if !isDACLProtected(t, path) {
		t.Fatal("newly created database DACL is not protected")
	}
	scope, err := currentSIDs()
	if err != nil {
		t.Fatal(err)
	}
	for _, ace := range readAllowACEs(t, path) {
		if !scope.trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			t.Fatalf("newly created database grants an untrusted principal 0x%x", uint32(ace.Mask))
		}
	}

	j2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer j2.Close()
	assertProposal(t, mustLoad(t, j2), want)
}

// TestWindowsPermissiveDatabaseRejectedWithoutChange proves an existing
// database whose DACL lets another principal read it is rejected and left
// byte-for-byte, DACL-for-DACL untouched.
func TestWindowsPermissiveDatabaseRejectedWithoutChange(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "journal.db")
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want := baseProposal()
	mustSave(t, j, want)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	setListAndWriteACE(t, path, everyone)
	before := mustReadFile(t, path)
	aclBefore := describeACL(t, path)

	if j, err := openBounded(t, path, 10*time.Second); j != nil || !errors.Is(err, ErrInvalid) {
		if j != nil {
			_ = j.Close()
		}
		t.Fatalf("Open(permissive db) = %v, %v; want ErrInvalid", j, err)
	}
	if got := mustReadFile(t, path); !bytes.Equal(got, before) {
		t.Fatal("rejecting a permissive database changed its bytes")
	}
	if got := describeACL(t, path); got != aclBefore {
		t.Fatalf("rejecting a permissive database repaired its DACL:\n%s\n%s", aclBefore, got)
	}
}

// TestWindowsPermissiveParentRejected proves a parent directory that grants an
// unrelated principal write rights is rejected and not re-permissioned.
func TestWindowsPermissiveParentRejected(t *testing.T) {
	dir := privateDir(t)
	makeParentShared(t, dir)
	before := describeACL(t, dir)

	if _, err := openBounded(t, filepath.Join(dir, "journal.db"), 10*time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Open(shared parent) = %v, want ErrInvalid", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "journal.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected Open left a database: %v", err)
	}
	if got := describeACL(t, dir); got != before {
		t.Fatalf("rejected Open changed the parent DACL:\n%s\n%s", before, got)
	}
}

// TestWindowsRejectsNetworkAndDeviceRoots documents the path-root rules.
func TestWindowsRejectsNetworkAndDeviceRoots(t *testing.T) {
	for _, path := range []string{
		`\\server\share\dir\journal.db`,
		`\\?\C:\dir\journal.db`,
		`\\.\C:\dir\journal.db`,
		`\dir\journal.db`,
	} {
		if why := localDriveRejection(path); why == "" {
			t.Fatalf("%q was accepted as a local drive path", path)
		}
		if err := checkLocalDrive(path); !errors.Is(err, ErrInvalid) {
			t.Fatalf("checkLocalDrive(%q) = %v, want ErrInvalid", path, err)
		}
	}
	dir := privateDir(t)
	if why := localDriveRejection(filepath.Join(dir, "journal.db")); why != "" {
		t.Fatalf("local path rejected: %s", why)
	}
}

// TestWindowsReparsePointRejected proves a symbolic-link parent or database
// name is rejected through the reparse-point checks.
func TestWindowsReparsePointRejected(t *testing.T) {
	real := privateDir(t)
	link := filepath.Join(privateDir(t), "link")
	mustLinkDir(t, real, link)
	if _, err := openBounded(t, filepath.Join(link, "journal.db"), 10*time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Open(link parent) = %v, want ErrInvalid", err)
	}
	if _, err := os.Lstat(filepath.Join(real, "journal.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open through a reparse point created a database: %v", err)
	}

	dir := privateDir(t)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	makeDBPrivate(t, target)
	mustLinkFile(t, target, filepath.Join(dir, "journal.db"))
	if _, err := openBounded(t, filepath.Join(dir, "journal.db"), 10*time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Open(link db) = %v, want ErrInvalid", err)
	}
}

func describeACL(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// TestWindowsReadableAncestorAcceptedStrictParentEnforced proves an ordinary
// ancestor that grants an untrusted principal read, list, traverse and
// add-new-child rights (like a user profile) is accepted, while the strict
// immediate parent rules still reject such a grant on the journal's own
// parent, and an ancestor DELETE right is still rejected.
func TestWindowsReadableAncestorAcceptedStrictParentEnforced(t *testing.T) {
	dir := privateDir(t)
	journalParent := filepath.Join(dir, "journal")
	if err := os.Mkdir(journalParent, 0o700); err != nil {
		t.Fatal(err)
	}
	defaultACL := describeACL(t, journalParent)
	t.Cleanup(func() { mustSetDACLString(t, journalParent, defaultACL) })

	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	defaultUserACE := sidRule(everyone, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE, 0)

	// An ordinary readable/traversable ancestor is not part of the secret.
	for _, entries := range [][]windows.EXPLICIT_ACCESS{
		{defaultUserACE},
		{sidRule(everyone, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE|
			windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA, 0)},
	} {
		if err := checkDirRulesForTest(t, journalParent, entries, false); err != nil {
			t.Fatalf("ancestor readable/traversable rules rejected: %v", err)
		}
	}

	// The same rules on the immediate parent are rejected: it must not let an
	// untrusted principal list, traverse, write, delete or change its ACL.
	for name, mask := range map[string]windows.ACCESS_MASK{
		"read-list":      windows.FILE_GENERIC_READ,
		"traverse":       windows.FILE_EXECUTE,
		"add-child":      windows.FILE_APPEND_DATA,
		"delete-child":   deleteChildMask,
		"rewrite-acl":    windows.WRITE_DAC,
		"rewrite-owner":  windows.WRITE_OWNER,
		"delete-folder":  windows.DELETE,
		"write-metadata": windows.FILE_WRITE_ATTRIBUTES,
	} {
		if err := checkDirRulesForTest(t, journalParent, []windows.EXPLICIT_ACCESS{sidRule(everyone, mask, 0)}, true); !errors.Is(err, ErrInvalid) {
			t.Fatalf("immediate parent rule %s = %v, want ErrInvalid", name, err)
		}
	}

	// Ancestors may not be replaceable or re-permissionable.
	for name, mask := range map[string]windows.ACCESS_MASK{
		"delete":              windows.DELETE,
		"delete-child":        deleteChildMask,
		"rewrite-acl":         windows.WRITE_DAC,
		"rewrite-owner":       windows.WRITE_OWNER,
		"write-metadata":      windows.FILE_WRITE_ATTRIBUTES,
		"generic-write":       windows.GENERIC_WRITE,
		"generic-all":         windows.GENERIC_ALL,
		"maximum-allowed":     maximumAllowed,
		"write-ext-attribute": windows.FILE_WRITE_EA,
	} {
		if err := checkDirRulesForTest(t, journalParent, []windows.EXPLICIT_ACCESS{sidRule(everyone, mask, 0)}, false); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ancestor rule %s = %v, want ErrInvalid", name, err)
		}
	}

	// Protected Users is not an administrator of this user's files.
	scope, err := currentSIDs()
	if err != nil {
		t.Fatal(err)
	}
	protectedUsers, err := windows.StringToSid("S-1-5-52")
	if err != nil {
		t.Fatal(err)
	}
	if scope.trusted(protectedUsers) {
		t.Fatal("Protected Users must not be a trusted principal")
	}
}

// checkDirRulesForTest compiles entries into a protected DACL on dir and runs
// the same directory rule check Open uses, restoring dir's DACL afterwards.
func checkDirRulesForTest(t *testing.T, dir string, entries []windows.EXPLICIT_ACCESS, immediate bool) error {
	t.Helper()
	sd, err := resetDACL(entries)
	if err != nil {
		return err
	}
	saved := describeACL(t, dir)
	mustSetDACL(t, dir, sd)
	defer mustSetDACLString(t, dir, saved)
	scope, err := currentSIDs()
	if err != nil {
		return err
	}
	current, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	forbidden := uint32(dirAncestorForbidden)
	if immediate {
		forbidden = dirImmediateForbidden
	}
	return scope.checkDirACL(dir, current, forbidden)
}

func mustSetDACLString(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	mustSetDACL(t, path, sd)
}

// TestWindowsAnyLocalDriveAccepted proves the drive rule is lexical: any
// absolute local drive letter is accepted, independent of the current drive.
func TestWindowsAnyLocalDriveAccepted(t *testing.T) {
	for _, path := range []string{
		`D:\dir\journal.db`,
		`Q:\a\b\journal.db`,
		`c:\dir\journal.db`,
	} {
		if why := localDriveRejection(path); why != "" {
			t.Fatalf("%q rejected lexically: %s", path, why)
		}
	}
	// Only the drive-type probe may refuse a drive letter that is not a local
	// fixed or RAM-disk volume (for example a disconnected mapped drive).
	for _, path := range []string{`Z:\dir\journal.db`, `Y:\dir\journal.db`} {
		err := checkLocalDrive(path)
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Fatalf("checkLocalDrive(%q) = %v, want nil or ErrInvalid", path, err)
		}
	}
}
