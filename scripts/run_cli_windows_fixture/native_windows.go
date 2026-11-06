package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func newPrivateRoot() (string, error) {
	parent, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		return "", err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return "", err
	}
	var value [16]byte
	if _, err = rand.Read(value[:]); err != nil {
		return "", err
	}
	path := filepath.Join(parent, "locklark-run-cli-acceptance-"+hex.EncodeToString(value[:]))
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	return path, windows.CreateDirectory(wide, &attributes)
}
func privateRoot(root string) error {
	bad := errors.New("private acceptance evidence unavailable")
	parent, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil || filepath.Clean(filepath.Dir(root)) != filepath.Clean(parent) || !strings.HasPrefix(filepath.Base(root), "locklark-run-cli-acceptance-") {
		return bad
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return bad
	}
	return filepath.Walk(root, func(path string, entry os.FileInfo, failure error) error {
		if failure != nil || entry.Mode()&os.ModeSymlink != 0 {
			return bad
		}
		wide, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return bad
		}
		attributes, err := windows.GetFileAttributes(wide)
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return bad
		}
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return bad
		}
		owner, _, err := sd.Owner()
		// Elevated Windows creators may assign Administrators as file owner.
		// Administrators are outside this protection boundary; ordinary access
		// still requires the exact current-user-only DACL checked below. The
		// newly created root itself always has the explicit current-user owner.
		if err != nil || owner == nil || !(owner.Equals(user.User.Sid) || path != root && owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
			return bad
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil || acl.AceCount != 1 {
			return bad
		}
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, 0, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
			return bad
		}
		if path == root {
			control, _, err := sd.Control()
			if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
				return bad
			}
		}
		return nil
	})
}
func consoleMode() (uint32, error) {
	name, err := windows.UTF16PtrFromString("CONIN$")
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)
	var mode uint32
	err = windows.GetConsoleMode(handle, &mode)
	return mode, err
}
func detachConsole(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
}
func detachOwnConsole() error {
	// Only the negative launcher calls this, never the ConPTY positive case.
	_, _, _ = windows.NewLazySystemDLL("kernel32.dll").NewProc("FreeConsole").Call()
	if !ownConsoleAbsent() {
		return errors.New("owned fixture remains attached to a console")
	}
	return nil
}
func ownConsoleAbsent() bool {
	codepage, _ := windows.GetConsoleCP()
	return codepage == 0
}
func ownProcessTree() error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, windows.CurrentProcess())
	}
	if err != nil {
		windows.CloseHandle(job)
	}
	// Deliberately process-lifetime: OS closure on exit kills owned descendants,
	// including when the controller aborts this exact launcher process handle.
	return err
}
