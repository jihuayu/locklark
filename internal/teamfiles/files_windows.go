package teamfiles

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

func descriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, file, private, immediate bool) error {
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
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !trusted(owner) {
		return ErrFile
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return ErrFile
	}
	danger := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | 0x0040)
	if file {
		danger |= windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
		if private {
			danger |= windows.GENERIC_READ | windows.FILE_READ_DATA
		}
	}
	if immediate {
		danger |= windows.GENERIC_WRITE | 0x0002 | 0x0004 | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, n, &ace) != nil {
			return ErrFile
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrFile
		}
		if uint32(ace.Mask)&danger != 0 && !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return ErrFile
		}
	}
	return nil
}
func chain(path string, file, private bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ErrFile
	}
	first := true
	for current := path; ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			return ErrFile
		}
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return ErrFile
		}
		attrs, err := windows.GetFileAttributes(name)
		if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrFile
		}
		if first && file {
			if !st.Mode().IsRegular() {
				return ErrFile
			}
		} else if !st.IsDir() {
			return ErrFile
		}
		sd, err := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		immediate := first && !file || !first && file && current == filepath.Dir(path)
		if err != nil || descriptor(sd, user.User.Sid, first && file, private, immediate) != nil {
			return ErrFile
		}
		first = false
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func trustedParent(path string) error             { return chain(path, false, true) }
func trustedFile(path string, private bool) error { return chain(path, true, private) }
func createLocalFile(path string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, ErrFile
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, ErrFile
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrFile
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attrs, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, ErrFile
	}
	return os.NewFile(uintptr(h), path), nil
}
func openLocalFile(path string, private bool) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, ErrFile
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrFile
	}
	after, err := f.Stat()
	user, ue := windows.GetCurrentProcessToken().GetTokenUser()
	var info windows.ByHandleFileInformation
	if err != nil || ue != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info) != nil || info.NumberOfLinks != 1 {
		f.Close()
		return nil, ErrFile
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor(sd, user.User.Sid, true, private, false) != nil {
		f.Close()
		return nil, ErrFile
	}
	return f, nil
}
func publishLocalFile(tmp, path string) error {
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
func equalPath(a, b string) bool { return strings.EqualFold(a, b) }
func validPlatformPath(path string) bool {
	if strings.HasPrefix(path, "\\\\?\\") || strings.HasPrefix(path, "\\\\.\\") {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, filepath.VolumeName(path)), "\\") {
		if part == "" {
			continue
		}
		if strings.Contains(part, ":") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
		base, _, _ := strings.Cut(strings.ToUpper(part), ".")
		switch base {
		case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³":
			return false
		}
	}
	return true
}
