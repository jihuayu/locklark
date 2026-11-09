package personal

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Restrict access at creation, before any helper config can be written. Child
// directories/files inherit the current-user-only access rule.
func createRunCLITemp() (string, error) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return "", e
	}
	// Unlike GetTempPath and os.TempDir, these resolve OS-known locations
	// rather than trusting TEMP/TMP/USERPROFILE environment text. LocalAppData
	// is the preferred private location. Public is a bounded fallback for
	// managed environments that grant another principal replacement rights on
	// the profile chain. Public may allow unrelated principals to create new
	// children, so the random child is created with its own current-user-only
	// DACL first and the complete resulting path is validated before use.
	var parents []string
	for _, folder := range []*windows.KNOWNFOLDERID{windows.FOLDERID_LocalAppData, windows.FOLDERID_Public} {
		parent, e := windows.KnownFolderPath(folder, 0)
		if e == nil {
			parents = append(parents, parent)
		}
	}
	if len(parents) == 0 {
		return "", ErrRunTemporary
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if e != nil {
		return "", e
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for _, parent := range parents {
		for attempt := 0; attempt < 16; attempt++ {
			id, e := randomID()
			if e != nil {
				return "", e
			}
			path := filepath.Join(parent, "locklark-run-cli-"+id)
			name, e := windows.UTF16PtrFromString(path)
			if e != nil {
				return "", e
			}
			e = windows.CreateDirectory(name, &attributes)
			if e == windows.ERROR_ALREADY_EXISTS || e == windows.ERROR_FILE_EXISTS {
				continue
			}
			if e != nil {
				break
			}
			if trustedRunCLITemporaryParent(path, user.User.Sid) == nil {
				return path, nil
			}
			if e = os.Remove(path); e != nil {
				return "", e
			}
			break
		}
	}
	return "", ErrRunTemporary
}

func runCLITrustedSID(sid, user *windows.SID) bool {
	if sid == nil {
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

func trustedRunCLIDirectoryDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, immediate bool) error {
	owner, _, e := sd.Owner()
	if e != nil || !runCLITrustedSID(owner, user) {
		return ErrRunTemporary
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return ErrRunTemporary
	}
	// Ancestors may allow unrelated new children, but cannot allow an
	// unrelated principal to replace an existing child or rewrite its ACL.
	dangerous := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x0040 /* FILE_DELETE_CHILD */)
	if immediate {
		dangerous |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			return ErrRunTemporary
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrRunTemporary
		}
		if uint32(ace.Mask)&dangerous != 0 && !runCLITrustedSID((*windows.SID)(unsafe.Pointer(&ace.SidStart)), user) {
			return ErrRunTemporary
		}
	}
	return nil
}

func trustedRunCLITemporaryParent(path string, user *windows.SID) error {
	volume := filepath.VolumeName(path)
	if !filepath.IsAbs(path) || len(volume) != 2 || volume[1] != ':' {
		return ErrRunTemporary
	}
	var chain []string
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		chain = append(chain, current)
		if filepath.Dir(current) == current {
			break
		}
	}
	// Trust each parent before looking up its child. No validated path
	// component is replaceable by another unprivileged Windows user.
	for i := len(chain) - 1; i >= 0; i-- {
		current := chain[i]
		wide, e := windows.UTF16PtrFromString(current)
		if e != nil {
			return ErrRunTemporary
		}
		attributes, e := windows.GetFileAttributes(wide)
		if e != nil || attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrRunTemporary
		}
		sd, e := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if e != nil || trustedRunCLIDirectoryDescriptor(sd, user, i == 0) != nil {
			return ErrRunTemporary
		}
	}
	return nil
}
