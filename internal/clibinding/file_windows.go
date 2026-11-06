//go:build windows

package clibinding

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsFileAccessMask = uint32(windows.FILE_READ_DATA | windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA | windows.FILE_READ_EA | windows.FILE_WRITE_EA |
	windows.FILE_READ_ATTRIBUTES | windows.FILE_WRITE_ATTRIBUTES |
	windows.FILE_EXECUTE | 0x0040 /* FILE_DELETE_CHILD */ | windows.DELETE |
	windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.SYNCHRONIZE | windows.GENERIC_READ | windows.GENERIC_WRITE |
	windows.GENERIC_EXECUTE | windows.GENERIC_ALL)

func trustedWindowsSID(sid, user *windows.SID) bool {
	if sid == nil || user == nil {
		return false
	}
	if sid.Equals(user) {
		return true
	}
	switch sid.String() {
	case "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464":
		return true // LocalSystem, Administrators, TrustedInstaller.
	}
	return false
}

func rejectReparse(path string) error {
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrBinding
	}
	attributes, err := windows.GetFileAttributes(wide)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrBinding
	}
	return nil
}

func trustedBindingDirectoryDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, immediate bool) error {
	owner, _, err := sd.Owner()
	if err != nil || !trustedWindowsSID(owner, user) {
		return ErrBinding
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return ErrBinding
	}
	dangerous := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.FILE_WRITE_EA |
		windows.FILE_WRITE_ATTRIBUTES | 0x0040 /* FILE_DELETE_CHILD */)
	if immediate {
		dangerous |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			return ErrBinding
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 ||
			ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrBinding
		}
		if uint32(ace.Mask)&dangerous != 0 &&
			!trustedWindowsSID((*windows.SID)(unsafe.Pointer(&ace.SidStart)), user) {
			return ErrBinding
		}
	}
	return nil
}

// trustedBindingParent walks every ancestor before trusting the immediate
// directory. A reparse point anywhere in the chain could redirect the write.
func trustedBindingParent(dir string) error {
	volume := filepath.VolumeName(dir)
	if !filepath.IsAbs(dir) || len(volume) != 2 || volume[1] != ':' {
		return ErrBinding
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ErrBinding
	}
	chain := make([]string, 0, 16)
	for current := filepath.Clean(dir); ; current = filepath.Dir(current) {
		chain = append(chain, current)
		if filepath.Dir(current) == current {
			break
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		current := chain[i]
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrBinding
		}
		if err = rejectReparse(current); err != nil {
			return ErrBinding
		}
		sd, err := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil || trustedBindingDirectoryDescriptor(sd, user.User.Sid, i == 0) != nil {
			return ErrBinding
		}
	}
	return nil
}

func privateBindingFileDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	owner, _, err := sd.Owner()
	if err != nil || !trustedWindowsSID(owner, user) {
		return ErrBinding
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return ErrBinding
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			return ErrBinding
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 ||
			ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrBinding
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user) && uint32(ace.Mask)&windowsFileAccessMask != 0 {
			return ErrBinding
		}
	}
	return nil
}

func validatePrivateBindingFile(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
		return nil, nil, ErrBinding
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Size() > maxBindingFileSize {
		return nil, nil, ErrBinding
	}
	if err = rejectReparse(path); err != nil {
		return nil, nil, ErrBinding
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, ErrBinding
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() ||
		after.Size() > maxBindingFileSize {
		file.Close()
		return nil, nil, ErrBinding
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		file.Close()
		return nil, nil, ErrBinding
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || privateBindingFileDescriptor(sd, user.User.Sid) != nil {
		file.Close()
		return nil, nil, ErrBinding
	}
	return file, after, nil
}

func readPrivateBindingFile(path string) ([]byte, error) {
	if err := trustedBindingParent(filepath.Dir(path)); err != nil {
		return nil, ErrBinding
	}
	file, _, err := validatePrivateBindingFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxBindingFileSize+1))
	if err != nil || len(raw) > maxBindingFileSize {
		clear(raw)
		return nil, ErrBinding
	}
	return raw, nil
}

func writePrivateBindingFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := trustedBindingParent(dir); err != nil {
		return ErrBinding
	}
	if _, _, err := validatePrivateBindingFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrBinding
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ErrBinding
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return ErrBinding
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	var temp string
	var file *os.File
	for attempt := 0; attempt < 16; attempt++ {
		suffix, suffixErr := randomTempSuffix()
		if suffixErr != nil {
			return suffixErr
		}
		temp = filepath.Join(dir, ".locklark-cli-"+suffix+".tmp")
		name, nameErr := windows.UTF16PtrFromString(temp)
		if nameErr != nil {
			return ErrBinding
		}
		handle, openErr := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if openErr == windows.ERROR_FILE_EXISTS || openErr == windows.ERROR_ALREADY_EXISTS {
			continue
		}
		if openErr != nil {
			return openErr
		}
		file = os.NewFile(uintptr(handle), temp)
		break
	}
	if file == nil {
		return ErrBinding
	}
	published := false
	defer func() {
		if !published {
			file.Close()
			os.Remove(temp)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return ErrBinding
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrBinding
	}
	if err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	published = true
	return nil
}
