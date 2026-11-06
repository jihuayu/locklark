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

type privatePolicyError string

func (e privatePolicyError) Error() string { return "private acceptance policy: " + string(e) }
func privateRootFailure(err error) string {
	if value, ok := err.(privatePolicyError); ok {
		return string(value)
	}
	return "unknown"
}
func privateRoot(root string) error {
	parent, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		return privatePolicyError("known-folder")
	}
	if filepath.Clean(filepath.Dir(root)) != filepath.Clean(parent) || !strings.HasPrefix(filepath.Base(root), "locklark-run-cli-acceptance-") {
		return privatePolicyError("known-folder-parent")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return privatePolicyError("user-token")
	}
	return filepath.Walk(root, func(path string, entry os.FileInfo, failure error) error {
		if failure != nil {
			return privatePolicyError("walk")
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return privatePolicyError("reparse")
		}
		wide, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return privatePolicyError("path")
		}
		attributes, err := windows.GetFileAttributes(wide)
		if err != nil {
			return privatePolicyError("attributes")
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return privatePolicyError("reparse")
		}
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return privatePolicyError("descriptor")
		}
		owner, _, err := sd.Owner()
		// Elevated Windows creators may assign Administrators as file owner.
		// Administrators are outside this protection boundary; ordinary access
		// still requires the exact current-user-only DACL checked below. The
		// newly created root itself always has the explicit current-user owner.
		if err != nil || owner == nil || !(owner.Equals(user.User.Sid) || path != root && owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
			return privatePolicyError("owner")
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil || acl.AceCount != 1 {
			return privatePolicyError("dacl")
		}
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, 0, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
			return privatePolicyError("dacl")
		}
		if path == root {
			control, _, err := sd.Control()
			if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
				return privatePolicyError("root-protection")
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
func isPipe(file *os.File) bool {
	kind, err := windows.GetFileType(windows.Handle(file.Fd()))
	return err == nil && kind == windows.FILE_TYPE_PIPE
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
