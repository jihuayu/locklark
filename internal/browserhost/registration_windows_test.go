package browserhost

import (
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
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
	dir := filepath.Join(newRegistrationTestRoot(t), "private")
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
	if err := trustedRegistrationParent(dir); err != nil {
		t.Fatalf("created directory ACL is not trusted: %v", err)
	}
	if err := trustedRegistrationFile(path, false); err != nil {
		t.Fatalf("created file ACL is not trusted: %v", err)
	}
}

// newRegistrationTestRoot uses the same private ACL creation path as the
// product below Windows' public directory. Its ancestors allow ordinary users
// to create children but not to replace existing children or modify their
// security metadata. Host TEMP directories can legitimately grant broader
// access, in which case the production trust check must reject the write; a
// security regression test cannot use that shared location as its fixture
// root.
func newRegistrationTestRoot(t *testing.T) string {
	t.Helper()
	parent, err := windows.KnownFolderPath(windows.FOLDERID_Public, 0)
	if err != nil {
		t.Fatal("Windows public directory unavailable:", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("Windows user unavailable:", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal("private test ACL unavailable:", err)
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	for attempt := 0; attempt < 16; attempt++ {
		var suffix [12]byte
		if _, err = rand.Read(suffix[:]); err != nil {
			t.Fatal("private test name unavailable:", err)
		}
		path := filepath.Join(parent, "locklark-registration-test-"+hex.EncodeToString(suffix[:]))
		wide, e := windows.UTF16PtrFromString(path)
		if e != nil {
			t.Fatal("private test path unavailable:", e)
		}
		e = windows.CreateDirectory(wide, &attributes)
		if e == windows.ERROR_ALREADY_EXISTS || e == windows.ERROR_FILE_EXISTS {
			continue
		}
		if e != nil {
			t.Fatal("private test directory unavailable:", e)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(path); err != nil {
				t.Error("private test cleanup failed:", err)
			}
		})
		return path
	}
	t.Fatal("private test directory name collision")
	return ""
}
