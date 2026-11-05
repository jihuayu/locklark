package browserhost

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"path/filepath"
	"testing"
)

func TestRegistrationWindowsACLRejectsOtherWriters(t *testing.T) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	sid := user.User.Sid.String()
	for _, other := range []string{"GW", "WD", "WO", "SD"} {
		sd, e := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;" + other + ";;;WD)")
		if e != nil {
			t.Fatal(e)
		}
		if registrationDescriptor(sd, user.User.Sid, true) == nil {
			t.Fatal("accepted unrelated file writer")
		}
	}
	readOnly, e := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;GR;;;WD)")
	if e != nil || registrationDescriptor(readOnly, user.User.Sid, true) != nil {
		t.Fatal("read-only metadata ACL refused", e)
	}
	writable, e := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;0x2;;;WD)")
	if e != nil {
		t.Fatal(e)
	}
	if registrationACL(writable, user.User.Sid, uint32(registry.SET_VALUE|registry.CREATE_SUB_KEY|windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER)) == nil {
		t.Fatal("registry allows unrelated set-value")
	}
	for _, right := range []string{"0x2", "0x4", "GW"} {
		directory, e := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;" + right + ";;;WD)")
		if e != nil {
			t.Fatal(e)
		}
		if registrationDescriptor(directory, user.User.Sid, false) == nil {
			t.Fatal("directory permits unrelated child creation")
		}
		if right != "GW" && registrationAncestorDescriptor(directory, user.User.Sid) != nil {
			t.Fatal("protected existing ancestor refused only-new-child rights")
		}
	}
	for _, right := range []string{"0x40", "SD", "WD", "WO", "GW"} {
		directory, e := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;" + right + ";;;WD)")
		if e != nil {
			t.Fatal(e)
		}
		if registrationAncestorDescriptor(directory, user.User.Sid) == nil {
			t.Fatal("ancestor permits replacing protected existing child")
		}
	}
}
func TestRegistrationWindowsPrivateCreation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if createRegistrationDirectory(dir) != nil {
		t.Fatal("private directory")
	}
	f, e := privateRegistrationTemp(dir)
	if e != nil {
		t.Fatal(e)
	}
	path := f.Name()
	if _, e = f.Write([]byte("metadata")); e != nil {
		t.Fatal(e)
	}
	f.Close()
	if trustedRegistrationParent(dir) != nil || trustedRegistrationFile(path, false) != nil {
		t.Fatal("created ACL is not trusted")
	}
}
