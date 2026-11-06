//go:build windows

package teamsync

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestAnchorWindowsDescriptorSeparatesPrivateFileAndAncestors(t *testing.T) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		access                   string
		file, immediate, allowed bool
	}{
		{"0x2", false, true, false}, // add file in publication parent
		{"0x4", false, true, false}, // add subdirectory in publication parent
		{"0x2", false, false, true}, // cannot replace an existing protected ancestor
		{"0x4", false, false, true},
		{"0x40", false, false, false}, // delete-child permits replacement
		{"0x1", true, false, false},   // private checkpoint bytes
		{"0x2", true, false, false},
	} {
		sd, e := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;" + tc.access + ";;;WD)")
		if e != nil {
			t.Fatal(e)
		}
		if e := anchorDescriptor(sd, user.User.Sid, tc.file, tc.immediate); (e == nil) != tc.allowed {
			t.Fatal("checkpoint ACL boundary accepted unsafe rights or refused safe ancestor")
		}
	}
}
