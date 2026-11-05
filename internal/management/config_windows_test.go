package management

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestConfigurationRejectsUntrustedWindowsGrants(t *testing.T) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	sid := user.User.Sid.String()
	for _, test := range []struct {
		sddl  string
		valid bool
	}{{"O:" + sid + "D:P(A;;GA;;;" + sid + ")", true}, {"O:" + sid + "D:P(A;;GA;;;WD)", false}, {"O:" + sid + "D:P(A;;GR;;;WD)(A;;GA;;;" + sid + ")", true}} {
		sd, e := windows.SecurityDescriptorFromString(test.sddl)
		if e != nil {
			t.Fatal(e)
		}
		if (trustedDescriptor(sd, user.User.Sid, true) == nil) != test.valid {
			t.Fatal("unexpected descriptor trust")
		}
	}
}
