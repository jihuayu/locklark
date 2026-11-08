//go:build windows

package main

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestReadTypedPersonalFileWindowsAcceptsOwnerPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "item.json")
	want := []byte(`{"title":"canary-private"}`)
	writePrivateTypedFixture(t, path, want)
	got, err := readTypedPersonalFile(path)
	if err != nil {
		t.Fatalf("read private owner-only file: %v", err)
	}
	defer clear(got)
	if string(got) != string(want) {
		t.Fatalf("unexpected content length %d", len(got))
	}
}

func TestReadTypedPersonalFileWindowsRefusesExtraEveryoneDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "item.json")
	writePrivateTypedFixture(t, path, []byte(`{"title":"canary"}`))
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current user SID: %v", err)
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatalf("everyone DACL descriptor: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("everyone DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatalf("install everyone DACL: %v", err)
	}
	raw, err := readTypedPersonalFile(path)
	if !errors.Is(err, errTypedInputRefused) || raw != nil {
		t.Fatalf("extra Everyone allow ACE was not refused: raw=%q err=%v", raw, err)
	}
}

func TestReadTypedPersonalFileWindowsRefusesDirectory(t *testing.T) {
	raw, err := readTypedPersonalFile(t.TempDir())
	if !errors.Is(err, errTypedInputRefused) || raw != nil {
		t.Fatalf("directory was not refused: raw=%q err=%v", raw, err)
	}
}
