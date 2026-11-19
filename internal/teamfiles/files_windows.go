package teamfiles

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
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

func verifyWindowsHandle(f *os.File, private bool, wantLinks uint64) error {
	if f == nil {
		return ErrFile
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ErrFile
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil ||
		uint64(info.NumberOfLinks) != wantLinks {
		return ErrFile
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor(sd, user.User.Sid, true, private, false) != nil {
		return ErrFile
	}
	return nil
}

func verifyWindowsFile(path string, owned os.FileInfo, private bool, wantLinks uint64) error {
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(owned, current) {
		return ErrFile
	}
	f, err := os.Open(path)
	if err != nil {
		return ErrFile
	}
	verifyErr := verifyWindowsHandle(f, private, wantLinks)
	info, statErr := f.Stat()
	closeErr := f.Close()
	if verifyErr != nil || statErr != nil || closeErr != nil || !os.SameFile(owned, info) {
		return ErrFile
	}
	return nil
}

func windowsParentBinding(path string, before os.FileInfo) error {
	if before == nil || trustedParent(path) != nil {
		return ErrFile
	}
	current, err := os.Stat(path)
	if err != nil || !current.IsDir() || !os.SameFile(before, current) {
		return ErrFile
	}
	return nil
}

// windowsParent holds one accepted directory handle for the whole publication.
// Every staging, publication, verification and cleanup operation is relative to
// this handle, so a later rename or replacement of the caller's directory path
// cannot redirect the operation or strand a path-based staging name.
type windowsParent struct {
	file   *os.File
	handle windows.Handle
	path   string
	held   os.FileInfo
}

func openWindowsParent(path string) (*windowsParent, error) {
	before, err := os.Stat(path)
	if err != nil || !before.IsDir() {
		return nil, ErrFile
	}
	if trustedParent(path) != nil {
		return nil, ErrFile
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, ErrFile
	}
	canonical = filepath.Clean(canonical)
	if trustedParent(canonical) != nil {
		return nil, ErrFile
	}
	canonicalInfo, err := os.Lstat(canonical)
	if err != nil || canonicalInfo.Mode()&os.ModeSymlink != 0 ||
		!canonicalInfo.IsDir() || !os.SameFile(before, canonicalInfo) {
		return nil, ErrFile
	}
	f, err := os.Open(canonical)
	if err != nil {
		return nil, ErrFile
	}
	held, err := f.Stat()
	if err != nil || !held.IsDir() || !os.SameFile(before, held) {
		f.Close()
		return nil, ErrFile
	}
	parent := &windowsParent{file: f, handle: windows.Handle(f.Fd()), path: path, held: held}
	if err := parent.bindingValid(); err != nil {
		f.Close()
		return nil, ErrFile
	}
	return parent, nil
}

func (p *windowsParent) Close() error {
	if p == nil || p.file == nil {
		return nil
	}
	return p.file.Close()
}

func (p *windowsParent) bindingValid() error {
	if p == nil || p.file == nil || p.held == nil || trustedParent(p.path) != nil {
		return ErrFile
	}
	current, err := os.Stat(p.path)
	if err != nil || !current.IsDir() || !os.SameFile(p.held, current) {
		return ErrFile
	}
	heldNow, err := p.file.Stat()
	if err != nil || !os.SameFile(p.held, heldNow) {
		return ErrFile
	}
	return nil
}

func windowsObjectAttributes(parent windows.Handle, name string) (windows.OBJECT_ATTRIBUTES, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.OBJECT_ATTRIBUTES{}, ErrFile
	}
	return windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}, nil
}

func createWindowsOwnedFileAt(parent windows.Handle, name string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return nil, ErrFile
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, ErrFile
	}
	attributes, err := windowsObjectAttributes(parent, name)
	if err != nil {
		return nil, ErrFile
	}
	attributes.SecurityDescriptor = sd
	// FILE_WRITE_THROUGH is requested on the owned staging inode in addition
	// to synchronous I/O. It is a filesystem/volume write-through request,
	// not a filesystem-independent power-loss proof; the explicit f.Sync
	// calls below are the actual handle flush boundaries this code observes.
	var handle windows.Handle
	err = windows.NtCreateFile(&handle,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|windows.SYNCHRONIZE,
		&attributes, &windows.IO_STATUS_BLOCK{}, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_CREATE,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_WRITE_THROUGH, 0, 0)
	if err != nil {
		return nil, ErrFile
	}
	f := os.NewFile(uintptr(handle), name)
	if f == nil {
		windows.CloseHandle(handle)
		return nil, ErrFile
	}
	if err := verifyWindowsHandle(f, true, 1); err != nil {
		_ = deleteWindowsHandle(handle)
		f.Close()
		return nil, ErrFile
	}
	return f, nil
}

func openWindowsAt(parent windows.Handle, name string, access, options uint32) (*os.File, error) {
	attributes, err := windowsObjectAttributes(parent, name)
	if err != nil {
		return nil, ErrFile
	}
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, access, &attributes, &windows.IO_STATUS_BLOCK{}, nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, options|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(handle), name)
	if f == nil {
		windows.CloseHandle(handle)
		return nil, ErrFile
	}
	return f, nil
}

func lstatWindowsAt(parent windows.Handle, name string) (os.FileInfo, error) {
	f, err := openWindowsAt(parent, name,
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE|windows.STANDARD_RIGHTS_READ,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	if err != nil {
		return nil, err
	}
	info, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil || closeErr != nil {
		return nil, ErrFile
	}
	return info, nil
}

func (p *windowsParent) verifyFile(name string, owned os.FileInfo, private bool, wantLinks uint64) error {
	current, err := lstatWindowsAt(p.handle, name)
	if err != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(owned, current) {
		return ErrFile
	}
	f, err := openWindowsAt(p.handle, name,
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE|windows.STANDARD_RIGHTS_READ,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	if err != nil {
		return ErrFile
	}
	info, statErr := f.Stat()
	verifyErr := verifyWindowsHandle(f, private, wantLinks)
	closeErr := f.Close()
	if statErr != nil || verifyErr != nil || closeErr != nil || !os.SameFile(owned, info) {
		return ErrFile
	}
	return nil
}

func (p *windowsParent) removeOwned(name string, owned os.FileInfo, wantLinks uint64) error {
	f, err := openWindowsAt(p.handle, name,
		windows.FILE_READ_ATTRIBUTES|windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	if err != nil {
		return ErrFile
	}
	handle := windows.Handle(f.Fd())
	info, statErr := f.Stat()
	var byHandle windows.ByHandleFileInformation
	infoErr := windows.GetFileInformationByHandle(handle, &byHandle)
	if statErr != nil || infoErr != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || !os.SameFile(owned, info) ||
		uint64(byHandle.NumberOfLinks) != wantLinks {
		f.Close()
		return ErrFile
	}
	deleteErr := deleteWindowsHandle(handle)
	closeErr := f.Close()
	if deleteErr != nil || closeErr != nil {
		return ErrFile
	}
	return nil
}

func windowsNotFound(err error) bool {
	if err == nil {
		return false
	}
	if status, ok := err.(windows.NTStatus); ok {
		switch status {
		case windows.STATUS_OBJECT_NAME_NOT_FOUND, windows.STATUS_OBJECT_PATH_NOT_FOUND:
			return true
		}
		switch status.Errno() {
		case syscall.ERROR_FILE_NOT_FOUND, syscall.ERROR_PATH_NOT_FOUND:
			return true
		}
	}
	return os.IsNotExist(err)
}

// windowsRenameInformation mirrors the native FILE_RENAME_INFORMATION aligned
// layout used by the NT rename information class. The leading union is an
// ULONG Flags (or BOOLEAN ReplaceIfExists), so its four-byte footprint and the
// following HANDLE alignment are preserved by the anonymous padding. On amd64
// and arm64 RootDirectory is at offset 8, FileNameLength at 16, FileName at 20
// and sizeof is 24; on 386 those offsets are 4, 8, 12 and sizeof is 16. The
// kernel consumes the declared FileNameLength and does not require FileName to
// be NUL-terminated, but the caller below allocates the documented
// sizeof(layout)+encoded-filename floor with the encoded terminator included
// as the bounded margin.
type windowsRenameInformation struct {
	ReplaceIfExists byte
	_               [unsafe.Sizeof(uintptr(0)) - 1]byte
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

// windowsRenameBuffer builds the exact bounded input buffer for
// FileRenameInformation. ReplaceIfExists stays false, RootDirectory remains the
// exact held parent handle, FileNameLength excludes the terminating NUL, and
// the complete bounded buffer length is passed to NtSetInformationFile by the
// caller.
func windowsRenameBuffer(parent windows.Handle, name string) ([]byte, []uint16, error) {
	name16, err := windows.UTF16FromString(name)
	if err != nil || len(name16) == 0 {
		return nil, nil, ErrFile
	}
	var layout windowsRenameInformation
	size := int(unsafe.Sizeof(layout))
	header := int(unsafe.Offsetof(layout.FileName))
	rootOffset := int(unsafe.Offsetof(layout.RootDirectory))
	lengthOffset := int(unsafe.Offsetof(layout.FileNameLength))
	// Keep the arithmetic bounded before converting the full buffer length to
	// the uint32 NtSetInformationFile accepts. The encoded filename retains its
	// NUL terminator, so this reserves both the documented structure floor and
	// a terminator margin without claiming the kernel reads beyond the declared
	// FileNameLength.
	if uint64(size)+uint64(len(name16))*2 > uint64(^uint32(0)) {
		return nil, nil, ErrFile
	}
	buffer := make([]byte, size+len(name16)*2)
	buffer[0] = 0 // ReplaceIfExists/Flags low byte: no replacement.
	*(*windows.Handle)(unsafe.Pointer(&buffer[rootOffset])) = parent
	*(*uint32)(unsafe.Pointer(&buffer[lengthOffset])) = uint32((len(name16) - 1) * 2)
	copy(buffer[header:], unsafe.Slice((*byte)(unsafe.Pointer(&name16[0])), len(name16)*2))
	return buffer, name16, nil
}

// renameWindowsNoReplace renames the staged file relative to the held parent
// handle without replacing any existing destination. Pinned os.Root.Rename
// replaces an existing destination on Windows, while os.Root.Link would both
// require hard-link support and lack the write-through barrier. The exposed
// x/sys NtSetInformationFile/FileRenameInformation pair with ReplaceIfExists=0
// is therefore the direct handle-relative no-replace primitive; it is not a
// pathname fallback and it works on filesystems without hard-link support.
func renameWindowsNoReplace(handle, parent windows.Handle, name string) error {
	buffer, _, err := windowsRenameBuffer(parent, name)
	if err != nil {
		return err
	}
	return windows.NtSetInformationFile(handle, &windows.IO_STATUS_BLOCK{}, &buffer[0],
		uint32(len(buffer)), windows.FileRenameInformation)
}

func deleteWindowsHandle(handle windows.Handle) error {
	disposition := struct{ Flags uint32 }{
		windows.FILE_DISPOSITION_DELETE |
			windows.FILE_DISPOSITION_POSIX_SEMANTICS |
			windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
	}
	err := windows.NtSetInformationFile(handle, &windows.IO_STATUS_BLOCK{},
		(*byte)(unsafe.Pointer(&disposition)), uint32(unsafe.Sizeof(disposition)),
		windows.FileDispositionInformationEx)
	if err == nil {
		return nil
	}
	switch err {
	case windows.STATUS_INVALID_INFO_CLASS, windows.STATUS_INVALID_PARAMETER, windows.STATUS_NOT_SUPPORTED:
		fallback := struct{ DeleteFile byte }{1}
		return windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo,
			(*byte)(unsafe.Pointer(&fallback)), 1)
	default:
		return ErrFile
	}
}

// writeNewAtPath creates, verifies and publishes the staged file entirely
// relative to one held parent handle. The private ACL is set by NtCreateFile at
// creation, not inherited or repaired by pathname afterwards. Publication is a
// no-replace handle-relative rename, so there is no second link to clean up;
// a failed or ambiguous rename only ever removes the owned staged name by
// handle-relative disposition. If the post-error final-name probe cannot
// verify either absence or a different inode, the outcome is Unknown rather
// than a definite refusal. File data is flushed before the rename and the
// file handle is flushed again after it. The staging handle also requests
// FILE_WRITE_THROUGH, but that is a filesystem/volume hint, not a
// filesystem-independent power-loss proof. Windows has no directory fsync, so
// a later binding or flush failure remains Unknown rather than claiming a
// durable publication, and an owned final name is never removed.
func writeNewAtPath(ctx context.Context, path string, raw []byte, staging string,
	hooks localWriteHooks) (retErr error) {
	parent, err := openWindowsParent(filepath.Dir(path))
	if err != nil {
		return ErrFile
	}
	defer parent.Close()
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return ErrFile
	}
	if _, err := lstatWindowsAt(parent.handle, name); err == nil {
		return ErrFile
	} else if !windowsNotFound(err) {
		return ErrFile
	}
	f, err := createWindowsOwnedFileAt(parent.handle, staging)
	if err != nil {
		return ErrFile
	}
	closed := false
	closeFile := func() error {
		if closed {
			return nil
		}
		closed = true
		return f.Close()
	}
	defer func() { _ = closeFile() }()
	owned, err := f.Stat()
	if err != nil {
		return ErrFile
	}
	finalLinked := false
	stagingPresent := true
	defer func() {
		if !stagingPresent {
			return
		}
		wantLinks := uint64(1)
		if finalLinked {
			wantLinks = 2
		}
		_ = parent.removeOwned(staging, owned, wantLinks)
	}()
	n, writeErr := f.Write(raw)
	syncErr := f.Sync()
	if writeErr != nil || n != len(raw) || syncErr != nil {
		return ErrFile
	}
	if err := verifyWindowsHandle(f, true, 1); err != nil {
		return ErrFile
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if hooks.beforeLink != nil {
		if err := hooks.beforeLink(); err != nil {
			return ErrFile
		}
	}
	if err := parent.bindingValid(); err != nil {
		return ErrFile
	}
	if _, err := lstatWindowsAt(parent.handle, name); err == nil {
		return ErrFile
	} else if !windowsNotFound(err) {
		return ErrFile
	}
	// This seam sits after the last binding and destination checks so a test
	// can cancel at the actual pre-rename boundary.
	if hooks.beforeCommit != nil {
		if err := hooks.beforeCommit(); err != nil {
			return ErrFile
		}
	}
	// A cancellation observed after the last binding and destination checks
	// must refuse the irreversible handle-relative rename before it is
	// issued. The deferred cleanup removes only the owned staged name; no
	// final binding appears.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := renameWindowsNoReplace(windows.Handle(f.Fd()), parent.handle, name); err != nil {
		final, statErr := lstatWindowsAt(parent.handle, name)
		// This seam runs only after the kernel rejected the no-replace rename.
		// A non-nil error replaces the real probe result and is fed to the
		// ordinary classification below; a nil result keeps the real probe.
		if hooks.failedRenameFinalProbe != nil {
			if probeErr := hooks.failedRenameFinalProbe(); probeErr != nil {
				final, statErr = nil, probeErr
			}
		}
		if statErr == nil && os.SameFile(owned, final) {
			finalLinked = true
			if staged, stageErr := lstatWindowsAt(parent.handle, staging); stageErr == nil &&
				os.SameFile(owned, staged) {
				if parent.removeOwned(staging, owned, 2) == nil {
					stagingPresent = false
				}
			} else if windowsNotFound(stageErr) {
				stagingPresent = false
			}
			_ = f.Sync()
			return ErrPublicationUnknown
		}
		if statErr == nil {
			// A different inode is definitely visible at the final name. That is
			// an ordinary no-replace refusal, not an uncertain publication.
			return ErrFile
		}
		if windowsNotFound(statErr) {
			// The final name is verified absent, so the failed rename did not
			// publish the owned staging inode.
			return ErrFile
		}
		// The final-name probe itself failed (for example a sharing violation,
		// I/O error, access denial or handle-close failure). Without a verified
		// absent or different final name, the failed rename cannot be
		// distinguished from one that made the owned inode visible. Do not
		// authorize an overwrite or recovery retry; only remove the known owned
		// staging name through the held parent.
		return ErrPublicationUnknown
	}
	finalLinked = true
	stagingPresent = false
	// The staged data was flushed before the rename; flush the handle again
	// after the name move, then prove the same owned inode is still behind this
	// handle and the held-parent final name. Either actual failure leaves the
	// visible final name in place and reports Unknown.
	if err := f.Sync(); err != nil {
		return ErrPublicationUnknown
	}
	if after, err := f.Stat(); err != nil || !os.SameFile(owned, after) {
		return ErrPublicationUnknown
	}
	if err := parent.verifyFile(name, owned, true, 1); err != nil {
		return ErrPublicationUnknown
	}
	if hooks.afterLink != nil {
		if err := hooks.afterLink(); err != nil {
			return ErrPublicationUnknown
		}
	}
	if err := parent.bindingValid(); err != nil {
		return ErrPublicationUnknown
	}
	if err := parent.verifyFile(name, owned, true, 1); err != nil {
		return ErrPublicationUnknown
	}
	if _, err := lstatWindowsAt(parent.handle, staging); !windowsNotFound(err) {
		return ErrPublicationUnknown
	}
	if hooks.afterPublish != nil {
		if err := hooks.afterPublish(); err != nil {
			return ErrPublicationUnknown
		}
	}
	if ctx.Err() != nil {
		return ErrPublicationUnknown
	}
	// The handle-relative rename already removed the staged name. The hook
	// names are retained for cross-platform tests; no second directory update
	// exists here.
	if hooks.afterUnlink != nil {
		if err := hooks.afterUnlink(); err != nil {
			return ErrPublicationUnknown
		}
	}
	if ctx.Err() != nil {
		return ErrPublicationUnknown
	}
	if hooks.beforeFinalSync != nil {
		if err := hooks.beforeFinalSync(); err != nil {
			return ErrPublicationUnknown
		}
	}
	if err := parent.bindingValid(); err != nil {
		return ErrPublicationUnknown
	}
	if err := f.Sync(); err != nil {
		return ErrPublicationUnknown
	}
	if ctx.Err() != nil {
		return ErrPublicationUnknown
	}
	if hooks.afterFinalSync != nil {
		if err := hooks.afterFinalSync(); err != nil {
			return ErrPublicationUnknown
		}
	}
	if ctx.Err() != nil {
		return ErrPublicationUnknown
	}
	if err := parent.bindingValid(); err != nil {
		return ErrPublicationUnknown
	}
	if err := closeFile(); err != nil {
		return ErrPublicationUnknown
	}
	if _, err := lstatWindowsAt(parent.handle, staging); !windowsNotFound(err) {
		return ErrPublicationUnknown
	}
	if err := parent.verifyFile(name, owned, true, 1); err != nil {
		return ErrPublicationUnknown
	}
	return nil
}

func readBoundedAtPath(ctx context.Context, path string, limit int64, private bool,
	hooks localReadHooks) ([]byte, error) {
	parentPath := filepath.Dir(path)
	before, err := os.Stat(parentPath)
	if err != nil || !before.IsDir() {
		return nil, ErrFile
	}
	if trustedParent(parentPath) != nil {
		return nil, ErrFile
	}
	canonical, err := filepath.EvalSymlinks(parentPath)
	if err != nil {
		return nil, ErrFile
	}
	canonicalInfo, err := os.Lstat(canonical)
	if err != nil || canonicalInfo.Mode()&os.ModeSymlink != 0 ||
		!canonicalInfo.IsDir() || !os.SameFile(before, canonicalInfo) {
		return nil, ErrFile
	}
	if hooks.afterCapture != nil {
		if err := hooks.afterCapture(); err != nil {
			return nil, ErrFile
		}
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return nil, ErrFile
	}
	defer root.Close()
	held, err := root.Stat(".")
	if err != nil || !held.IsDir() || !os.SameFile(before, held) {
		return nil, ErrFile
	}
	binding := func() error {
		if trustedParent(parentPath) != nil {
			return ErrFile
		}
		current, err := os.Stat(parentPath)
		if err != nil || !os.SameFile(held, current) {
			return ErrFile
		}
		heldNow, err := root.Stat(".")
		if err != nil || !os.SameFile(held, heldNow) {
			return ErrFile
		}
		return nil
	}
	if err := binding(); err != nil {
		return nil, ErrFile
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return nil, ErrFile
	}
	f, err := root.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, ErrFile
	}
	owned, err := f.Stat()
	if err != nil || verifyWindowsHandle(f, private, 1) != nil {
		f.Close()
		return nil, ErrFile
	}
	named, err := root.Lstat(name)
	if err != nil || !os.SameFile(owned, named) {
		f.Close()
		return nil, ErrFile
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) > limit {
		clear(raw)
		return nil, ErrFile
	}
	if hooks.afterOpen != nil {
		if err := hooks.afterOpen(); err != nil {
			clear(raw)
			return nil, ErrFile
		}
	}
	if ctx.Err() != nil {
		clear(raw)
		return nil, ctx.Err()
	}
	if err := binding(); err != nil {
		clear(raw)
		return nil, ErrFile
	}
	named, err = root.Lstat(name)
	if err != nil || !os.SameFile(owned, named) {
		clear(raw)
		return nil, ErrFile
	}
	named, err = os.Lstat(path)
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(owned, named) {
		clear(raw)
		return nil, ErrFile
	}
	return raw, nil
}
