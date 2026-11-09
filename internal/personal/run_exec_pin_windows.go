//go:build windows

package personal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// maxRunBundleProgramBytes bounds how large a program image may be when it is
// pinned. Larger images are refused before any child starts.
const maxRunBundleProgramBytes = 1 << 30

// runBundlePinnedProgram is the Windows exact-image pin.
//
// Windows has no public primitive that starts a process from an open file
// handle (there is no fexecve equivalent and no documented way to hand
// CreateProcess a handle instead of a name), so the child is still started from
// the caller-visible path. The pin therefore makes that pathname unusable by
// anybody else for the child's whole lifetime instead of pointing at a private
// copy:
//
//   - image is an open GENERIC_READ handle whose share mode allows only further
//     readers. Any later open that asks for write access (truncate, in-place
//     overwrite, append, attribute write) or for DELETE access (rename, delete,
//     replace) fails with a sharing violation until the child has exited. The
//     handle is held for the entire cmd.Run, not just up to Start.
//   - ancestry holds one open handle per ancestor directory of the program,
//     opened the same deny-write/deny-delete way. Renaming, deleting or
//     replacing any directory on the path needs DELETE access on that
//     directory, so neither the image nor any parent can be swapped out from
//     under the name CreateProcess resolves.
//   - the guard handles are opened before the image is read, so the digest
//     compared against the approval is computed from the same file object the
//     guard already protects, and the name is re-resolved from the handle
//     (GetFinalPathNameByHandle) instead of being trusted.
//
// Sharing rules are per file object, not per process, so the same guarantee
// covers another process and a second handle in this process. The trust
// boundary that remains is the current user, exactly as with the Linux sealed
// memfd pin: a same-user process can inject into or debug this process.
type runBundlePinnedProgram struct {
	image    *os.File
	ancestry []windows.Handle
}

// close releases the image guard and every directory guard. It is safe to call
// more than once.
func (p *runBundlePinnedProgram) close() {
	if p == nil {
		return
	}
	if p.image != nil {
		_ = p.image.Close()
		p.image = nil
	}
	for _, handle := range p.ancestry {
		_ = windows.CloseHandle(handle)
	}
	p.ancestry = nil
}

// hashPinnedRunBundleProgram hashes exactly size bytes of the pinned image from
// the start of the file. It reads through the guard handle, so it can never
// describe a different file than the one being protected.
func hashPinnedRunBundleProgram(file *os.File, size int64) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", ErrRunResult
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, maxRunBundleProgramBytes+1))
	if err != nil || n != size || n > maxRunBundleProgramBytes {
		return "", ErrRunResult
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// windowsHandlePath returns the fully resolved DOS path of an open handle. Every
// component (symlink, junction, mount point, short name) is resolved by the
// kernel, so the caller can require that the object it pinned is the object the
// caller-visible name still denotes.
func windowsHandlePath(handle windows.Handle) (string, error) {
	size := uint32(512)
	for {
		buf := make([]uint16, size)
		// Flags 0 selects VOLUME_NAME_DOS and FILE_NAME_NORMALIZED.
		n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), 0)
		if err != nil || n == 0 {
			return "", ErrRunResult
		}
		if int(n) < len(buf) {
			path := windows.UTF16ToString(buf[:n])
			switch {
			case strings.HasPrefix(path, `\\?\UNC\`):
				path = `\\` + strings.TrimPrefix(path, `\\?\UNC\`)
			case strings.HasPrefix(path, `\\?\`):
				path = strings.TrimPrefix(path, `\\?\`)
			case strings.HasPrefix(path, `\??\`):
				path = strings.TrimPrefix(path, `\??\`)
			}
			return path, nil
		}
		if n > 32<<10 {
			return "", ErrRunResult
		}
		size = n + 1
	}
}

// sameRunBundleProgramImage reports whether two looks through the guard handle
// describe the same untouched file.
func sameRunBundleProgramImage(before, after windows.ByHandleFileInformation) bool {
	return before.FileAttributes == after.FileAttributes &&
		before.VolumeSerialNumber == after.VolumeSerialNumber &&
		before.FileIndexHigh == after.FileIndexHigh && before.FileIndexLow == after.FileIndexLow &&
		before.FileSizeHigh == after.FileSizeHigh && before.FileSizeLow == after.FileSizeLow &&
		before.LastWriteTime == after.LastWriteTime
}

// pinRunBundleProgram opens the approved executable once, verifies that the
// opened object is the ordinary file the caller named below a non-replaceable
// ancestry, and, when the caller supplied a digest, verifies the exact bytes.
// The returned guards must stay open until the child has exited.
func pinRunBundleProgram(program string, expectedSHA256 string) (*runBundlePinnedProgram, error) {
	if !filepath.IsAbs(program) || len(program) > 4096 || !strings.EqualFold(filepath.Ext(program), ".exe") {
		return nil, ErrRunResult
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, ErrRunResult
	}
	name, err := windows.UTF16PtrFromString(program)
	if err != nil {
		return nil, ErrRunResult
	}
	// GENERIC_READ with FILE_SHARE_READ only, and deliberately no
	// FILE_SHARE_WRITE and no FILE_SHARE_DELETE: this is the whole pin.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, ErrRunResult
	}
	pinned := &runBundlePinnedProgram{image: os.NewFile(uintptr(handle), "locklark-run-program")}
	if pinned.image == nil {
		_ = windows.CloseHandle(handle)
		return nil, ErrRunResult
	}
	if err = pinned.verify(program, expectedSHA256, user.User.Sid); err != nil {
		pinned.close()
		return nil, err
	}
	return pinned, nil
}

// verify checks one already-open image guard plus the ancestry the caller named,
// and returns ErrRunResult for anything that cannot be proven.
func (p *runBundlePinnedProgram) verify(program, expectedSHA256 string, sid *windows.SID) error {
	handle := windows.Handle(p.image.Fd())
	var before windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &before); err != nil {
		return ErrRunResult
	}
	if before.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return ErrRunResult
	}
	size := int64(before.FileSizeHigh)<<32 | int64(before.FileSizeLow)
	if size <= 0 || size > maxRunBundleProgramBytes {
		return ErrRunResult
	}
	// The name handed to CreateProcess must still resolve to the object that was
	// opened, hashed and guarded. A reparse point, a swapped junction or a short
	// name that reaches another image is refused instead of executed.
	final, err := windowsHandlePath(handle)
	if err != nil || !strings.EqualFold(final, filepath.Clean(program)) {
		return ErrRunResult
	}
	// Only trusted principals may be able to rewrite the image or its access
	// rule. The current user, SYSTEM, Administrators and TrustedInstaller are
	// trusted; any other principal holding write, DELETE, WRITE_DAC or
	// WRITE_OWNER rights makes the image replaceable and is refused.
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || trustedRunCLIDirectoryDescriptor(descriptor, sid, true) != nil {
		return ErrRunResult
	}
	if err = p.guardAncestry(program, sid); err != nil {
		return err
	}
	digest, err := hashPinnedRunBundleProgram(p.image, size)
	if err != nil {
		return err
	}
	// A writer that was already open before this pin could still have reached
	// the file while the digest was read. The share mode stops every new writer;
	// this second look through the same handle additionally refuses an image
	// whose identity, length, attributes or write time moved during the read.
	var after windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &after); err != nil || !sameRunBundleProgramImage(before, after) {
		return ErrRunResult
	}
	if expectedSHA256 != "" && digest != expectedSHA256 {
		return ErrRunResult
	}
	return nil
}

// guardAncestry proves that no ancestor directory of the program can be renamed
// or replaced by an untrusted principal and then holds each of them open with
// deny-delete sharing until the pin is released.
func (p *runBundlePinnedProgram) guardAncestry(program string, sid *windows.SID) error {
	parent := filepath.Dir(filepath.Clean(program))
	// The same owner/ACL policy the private run root uses: every ancestor must be
	// owned by a trusted principal, must not be a reparse point, and must not let
	// an untrusted principal replace an existing child or rewrite its access
	// rule. A program below a directory that any other user can rename or
	// rewrite is refused rather than claimed as pinned.
	if err := trustedRunCLITemporaryParent(parent, sid); err != nil {
		return ErrRunResult
	}
	var chain []string
	for current := parent; ; current = filepath.Dir(current) {
		chain = append(chain, current)
		if filepath.Dir(current) == current {
			break
		}
	}
	// Open from the volume root downwards so every guard is in place before the
	// next, deeper component is looked at.
	for i := len(chain) - 1; i >= 0; i-- {
		dir := chain[i]
		name, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return ErrRunResult
		}
		// FILE_FLAG_BACKUP_SEMANTICS is required to open a directory object, and
		// the share mode is what refuses a later DELETE access on it, which a
		// rename or delete of the directory requires.
		handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return ErrRunResult
		}
		p.ancestry = append(p.ancestry, handle)
		var info windows.ByHandleFileInformation
		if err = windows.GetFileInformationByHandle(handle, &info); err != nil ||
			info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
			info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrRunResult
		}
		if final, err := windowsHandlePath(handle); err != nil || !strings.EqualFold(final, dir) {
			return ErrRunResult
		}
	}
	return nil
}

// newRunBundleCommand pins the program image and its ancestry when the caller
// approved a digest, and returns a command that starts the caller-named
// executable directly. The caller's Args[0], working directory, environment,
// standard streams and deadline context are untouched: there is no shell,
// interpreter or capture wrapper, and no fallback path for a failed pin.
//
// An empty expectedSHA256 is the explicit unpinned scope, matching Linux: the
// original path is executed directly and no image or ancestry handle is held.
// The cheap local policy still applies (absolute path and an existing regular,
// non-empty .exe named by lstat), but there is no ACL rewrite, lock or pin. A
// caller that supplies a digest always goes through pinRunBundleProgram and is
// refused if any part of the pin cannot be proven.
func newRunBundleCommand(ctx context.Context, program string, args []string, expectedSHA256 string) (*exec.Cmd, func(), error) {
	if expectedSHA256 == "" {
		info, err := os.Lstat(program)
		if err != nil || !filepath.IsAbs(program) || len(program) > 4096 ||
			!strings.EqualFold(filepath.Ext(program), ".exe") ||
			!info.Mode().IsRegular() || info.Size() <= 0 {
			return nil, nil, ErrRunResult
		}
		return exec.CommandContext(ctx, program, args...), func() {}, nil
	}
	pinned, err := pinRunBundleProgram(program, expectedSHA256)
	if err != nil {
		return nil, nil, err
	}
	// syscall.StartProcess passes this path as CreateProcess's
	// lpApplicationName, so there is no PATH or extension search; the guard
	// handles keep that name bound to the verified bytes until closeProgram runs
	// after the child has exited.
	cmd := exec.CommandContext(ctx, program, args...)
	return cmd, pinned.close, nil
}
