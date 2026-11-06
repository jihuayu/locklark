package personal

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestRunCLIWindowsPrivateDirectory(t *testing.T) {
	known, e := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if e != nil {
		t.Fatal("OS user directory unavailable")
	}
	poison := t.TempDir()
	for _, name := range []string{"TMP", "TEMP", "USERPROFILE", "LOCALAPPDATA"} {
		t.Setenv(name, poison)
	}
	root, e := createRunCLITemp()
	if e != nil {
		t.Fatal("private root unavailable")
	}
	defer os.RemoveAll(root)
	if filepath.Dir(root) != filepath.Clean(known) {
		t.Fatal("temporary root used caller environment instead of the OS directory")
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal("user unavailable")
	}
	sd, e := windows.GetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal("directory protection unavailable")
	}
	control, _, e := sd.Control()
	if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("directory DACL is not protected")
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount != 1 {
		t.Fatal("directory access rule is not exclusive")
	}
	var allowed *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(acl, 0, &allowed) != nil || allowed.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || allowed.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != (windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) {
		t.Fatal("directory inheritance is not private")
	}
	sid := (*windows.SID)(unsafe.Pointer(&allowed.SidStart))
	if !sid.Equals(user.User.Sid) {
		t.Fatal("directory access belongs to another user")
	}
	child := filepath.Join(root, "inherited-child")
	if os.Mkdir(child, 0700) != nil {
		t.Fatal("inherited directory unavailable")
	}
	childSD, e := windows.GetNamedSecurityInfo(child, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal("inherited access rule unavailable")
	}
	childACL, _, e := childSD.DACL()
	if e != nil || childACL == nil || childACL.AceCount != 1 {
		t.Fatal("inherited access is not exclusive")
	}
	var childACE *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(childACL, 0, &childACE) != nil || childACE.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !(*windows.SID)(unsafe.Pointer(&childACE.SidStart)).Equals(user.User.Sid) {
		t.Fatal("child did not inherit current-user-only access")
	}
	if trustedRunCLITemporaryParent(child, user.User.Sid) != nil {
		t.Fatal("inherited child has replaceable ancestry")
	}
}

func TestRunCLIWindowsRejectsReplaceableAncestor(t *testing.T) {
	root, e := createRunCLITemp()
	if e != nil {
		t.Fatal("private root unavailable")
	}
	defer os.RemoveAll(root)
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal("user unavailable")
	}
	create := func(path, acl string) {
		sd, e := windows.SecurityDescriptorFromString(acl)
		if e != nil {
			t.Fatal("ACL fixture unavailable")
		}
		attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		wide, e := windows.UTF16PtrFromString(path)
		if e != nil || windows.CreateDirectory(wide, &attrs) != nil {
			t.Fatal("directory fixture unavailable")
		}
	}
	unsafeParent := filepath.Join(root, "public")
	create(unsafeParent, "D:P(A;OICI;FA;;;"+user.User.Sid.String()+")(A;OICI;FA;;;WD)")
	privateLeaf := filepath.Join(unsafeParent, "private")
	create(privateLeaf, "D:P(A;OICI;FA;;;"+user.User.Sid.String()+")")
	// Independently confirm that the real parent permits Everyone to remove
	// an existing child, even though that child itself has a private DACL.
	sd, e := windows.GetNamedSecurityInfo(unsafeParent, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal("ACL fixture unreadable")
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		t.Fatal("ACL fixture unreadable")
	}
	publicDelete := false
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			t.Fatal("ACL fixture unreadable")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && sid.String() == "S-1-1-0" && ace.Mask&0x0040 != 0 {
			publicDelete = true
		}
	}
	if !publicDelete {
		t.Fatal("fixture does not permit cross-user child replacement")
	}
	for _, parent := range []string{unsafeParent, privateLeaf} {
		if trustedRunCLITemporaryParent(parent, user.User.Sid) != ErrRunTemporary {
			t.Fatal("replaceable temporary ancestry accepted")
		}
	}
}
