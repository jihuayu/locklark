//go:build windows

package main

import (
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func configDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, file, private bool) error {
	trusted := func(sid *windows.SID) bool {
		if sid.Equals(user) {
			return true
		}
		switch sid.String() {
		case "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464":
			return true
		}
		return false
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !trusted(owner) {
		return errCommand
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return errCommand
	}
	dangerous := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | 0x0040)
	if file {
		dangerous |= windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
		if private {
			dangerous |= windows.GENERIC_READ | windows.FILE_READ_DATA
		}
	}
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, n, &ace) != nil {
			return errCommand
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || uint32(ace.Mask)&dangerous != 0 && !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return errCommand
		}
	}
	return nil
}
func readLocalFile(path string, limit int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errCommand
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, errCommand
	}
	first := true
	for current := path; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return nil, errCommand
		}
		if first {
			if !st.Mode().IsRegular() || st.Size() > limit {
				return nil, errCommand
			}
		} else if !st.IsDir() {
			return nil, errCommand
		}
		sd, e := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if e != nil || configDescriptor(sd, user.User.Sid, first, private) != nil {
			return nil, errCommand
		}
		first = false
		if filepath.Dir(current) == current {
			break
		}
	}
	before, e := os.Lstat(path)
	if e != nil {
		return nil, errCommand
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, errCommand
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Size() > limit {
		return nil, errCommand
	}
	sd, e := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || configDescriptor(sd, user.User.Sid, true, private) != nil {
		return nil, errCommand
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(raw)) > limit {
		return nil, errCommand
	}
	return raw, nil
}
