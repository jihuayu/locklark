//go:build windows

package teamfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privateWindowsUser(t *testing.T) *windows.SID {
	t.Helper()
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("PRIVATE_WINDOWS_CURRENT_USER_UNAVAILABLE")
	}
	return token.User.Sid
}

func privateWindowsSD(t *testing.T, sddl string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal("PRIVATE_WINDOWS_SD_FIXTURE_FAILED")
	}
	return sd
}

func privateWindowsCreateDir(t *testing.T, path, sddl string) {
	t.Helper()
	sd := privateWindowsSD(t, sddl)
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("PRIVATE_WINDOWS_PATH_FIXTURE_FAILED")
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		t.Fatal("PRIVATE_WINDOWS_DIRECTORY_FIXTURE_FAILED")
	}
}

func privateWindowsCreateFile(t *testing.T, path, sddl string) {
	t.Helper()
	sd := privateWindowsSD(t, sddl)
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("PRIVATE_WINDOWS_PATH_FIXTURE_FAILED")
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal("PRIVATE_WINDOWS_FILE_FIXTURE_FAILED")
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal("PRIVATE_WINDOWS_FILE_FIXTURE_CLOSE_FAILED")
	}
}

func privateWindowsNamedSD(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal("PRIVATE_WINDOWS_NAMED_SD_FAILED")
	}
	return sd
}

func privateWindowsSDDL(t *testing.T, path string) string {
	t.Helper()
	return privateWindowsNamedSD(t, path).String()
}

func TestPrivateWindowsDirectoryDescriptorPolicy(t *testing.T) {
	user := privateWindowsUser(t)
	sid := user.String()
	owner := "O:" + sid
	cases := []struct {
		name    string
		sddl    string
		allowed bool
	}{
		{"user-protected", owner + "D:P(A;OICI;FA;;;" + sid + ")", true},
		{"system-trusted", owner + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)", true},
		{"admin-trusted", owner + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;BA)", true},
		{"trusted-installer", owner + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)", true},
		{"foreign-owner", "O:S-1-1-0D:P(A;OICI;FA;;;" + sid + ")", false},
		{"everyone-read-list", owner + "D:P(A;;FA;;;" + sid + ")(A;;GR;;;WD)", false},
		{"everyone-traverse", owner + "D:P(A;;FA;;;" + sid + ")(A;;0x20;;;WD)", false},
		{"everyone-read-attributes", owner + "D:P(A;;FA;;;" + sid + ")(A;;0x80;;;WD)", false},
		{"builtin-users-write", owner + "D:P(A;;FA;;;" + sid + ")(A;;0x2;;;S-1-5-32-545)", false},
		{"everyone-inherit-read", owner + "D:P(A;;FA;;;" + sid + ")(A;OICIIO;GR;;;WD)", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sd := privateWindowsSD(t, tc.sddl)
			if got := privateDirectoryDescriptor(sd, user) == nil; got != tc.allowed {
				t.Fatalf("PRIVATE_WINDOWS_DIRECTORY_DESCRIPTOR_MISMATCH allowed=%t", got)
			}
		})
	}
}

func TestPrivateWindowsEnsureCreatesProtectedUserDACL(t *testing.T) {
	user := privateWindowsUser(t)
	path := filepath.Join(t.TempDir(), "workspace")
	if err := EnsurePrivateWorkspace(path); err != nil {
		t.Fatal("PRIVATE_WINDOWS_ENSURE_CREATE_FAILED")
	}
	if err := ValidatePrivateWorkspace(path); err != nil {
		t.Fatal("PRIVATE_WINDOWS_ENSURE_VALIDATE_FAILED")
	}
	sd := privateWindowsNamedSD(t, path)
	if !strings.Contains(sd.String(), "D:P") {
		t.Fatal("PRIVATE_WINDOWS_CREATED_DACL_NOT_PROTECTED")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(user) {
		t.Fatal("PRIVATE_WINDOWS_CREATED_OWNER_MISMATCH")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		t.Fatal("PRIVATE_WINDOWS_CREATED_DACL_MISSING")
	}
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, n, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatal("PRIVATE_WINDOWS_CREATED_DACL_SHAPE_INVALID")
		}
		if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)); !sid.Equals(user) {
			t.Fatal("PRIVATE_WINDOWS_CREATED_DACL_NOT_USER_ONLY")
		}
	}
}

func TestPrivateWindowsEnsureRejectsExistingBroadACLWithoutRepair(t *testing.T) {
	user := privateWindowsUser(t)
	sid := user.String()
	for _, tc := range []struct {
		name string
		acl  string
	}{
		{"read", "D:P(A;OICI;FA;;;" + sid + ")(A;;GR;;;WD)"},
		{"inherit-read", "D:P(A;OICI;FA;;;" + sid + ")(A;OICIIO;GR;;;WD)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "existing")
			privateWindowsCreateDir(t, path, "O:"+sid+tc.acl)
			before := privateWindowsSDDL(t, path)
			if EnsurePrivateWorkspace(path) == nil {
				t.Fatal("PRIVATE_WINDOWS_ENSURE_ACCEPTED_BROAD_ACL")
			}
			if after := privateWindowsSDDL(t, path); after != before {
				t.Fatal("PRIVATE_WINDOWS_ENSURE_REPAIRED_EXISTING_ACL")
			}
		})
	}
}

func TestPrivateWindowsFilePrivateReadRequired(t *testing.T) {
	user := privateWindowsUser(t)
	sid := user.String()
	root := t.TempDir()
	good := filepath.Join(root, "good")
	privateWindowsCreateFile(t, good, "O:"+sid+"D:P(A;;FA;;;"+sid+")")
	if err := ValidatePrivateFile(good); err != nil {
		t.Fatal("PRIVATE_WINDOWS_PRIVATE_FILE_REJECTED")
	}
	broad := filepath.Join(root, "broad")
	privateWindowsCreateFile(t, broad, "O:"+sid+"D:P(A;;FA;;;"+sid+")(A;;GR;;;WD)")
	before := privateWindowsSDDL(t, broad)
	if ValidatePrivateFile(broad) == nil {
		t.Fatal("PRIVATE_WINDOWS_FILE_BROAD_READ_ACCEPTED")
	}
	if after := privateWindowsSDDL(t, broad); after != before {
		t.Fatal("PRIVATE_WINDOWS_FILE_BROAD_READ_CHANGED")
	}
}

func TestPrivateWindowsRejectsWrongShapeAndReparse(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dir")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("PRIVATE_WINDOWS_DIRECTORY_FIXTURE_FAILED")
	}
	if ValidatePrivateFile(dir) == nil {
		t.Fatal("PRIVATE_WINDOWS_FILE_ACCEPTED_DIRECTORY")
	}
	file := filepath.Join(root, "file")
	user := privateWindowsUser(t)
	sid := user.String()
	privateWindowsCreateFile(t, file, "O:"+sid+"D:P(A;;FA;;;"+sid+")")
	if ValidatePrivateWorkspace(file) == nil {
		t.Fatal("PRIVATE_WINDOWS_DIRECTORY_ACCEPTED_FILE")
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal("PRIVATE_WINDOWS_DIRECTORY_FIXTURE_FAILED")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal("PRIVATE_WINDOWS_REPARSE_FIXTURE_FAILED")
	}
	if ValidatePrivateWorkspace(link) == nil {
		t.Fatal("PRIVATE_WINDOWS_DIRECTORY_ACCEPTED_REPARSE")
	}
	if EnsurePrivateWorkspace(link) == nil {
		t.Fatal("PRIVATE_WINDOWS_ENSURE_ACCEPTED_REPARSE")
	}
}
