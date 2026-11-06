package teamfiles

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestTransferWindowsRejectsStreamAndDeviceAliases(t *testing.T) {
	for _, path := range []string{"C:\\private\\record:stream", "C:\\private\\record.", "C:\\private\\record ", "C:\\private\\NUL.json", "\\\\?\\C:\\private\\record", "\\\\.\\CON"} {
		if ValidPath(path) {
			t.Fatal("Windows stream or normalized device alias accepted")
		}
	}
	if !ValidPath("C:\\private\\record.json") {
		t.Fatal("canonical Windows transfer refused")
	}
}
func TestTransferWindowsDescriptorRejectsForeignReadAndReplaceRights(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("current user unavailable")
	}
	for _, tc := range []struct {
		rights                            string
		file, private, immediate, allowed bool
	}{
		{"0x1", true, true, false, false}, {"0x1", true, false, false, true}, {"0x2", false, true, true, false}, {"0x40", false, true, false, false}, {"0x2", false, true, false, true},
	} {
		sd, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;" + tc.rights + ";;;WD)")
		if err != nil {
			t.Fatal("descriptor setup")
		}
		if (descriptor(sd, user.User.Sid, tc.file, tc.private, tc.immediate) == nil) != tc.allowed {
			t.Fatal("private transfer or trusted ancestor rights boundary incorrect")
		}
	}
}
