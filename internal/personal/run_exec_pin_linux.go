//go:build linux

package personal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// maxRunBundleProgramBytes bounds how large a program image may be when it is
// copied into the sealed execution snapshot. Larger images are refused before
// any child starts.
const maxRunBundleProgramBytes = 1 << 30

// runBundlePinnedProgram is one sealed, anonymous in-memory copy of the exact
// program image. The caller-visible path is only read once; execution is bound
// to this snapshot, so a later rename, truncate or in-place write cannot change
// the bytes the child runs.
type runBundlePinnedProgram struct {
	file *os.File
}

func (p *runBundlePinnedProgram) close() {
	if p != nil && p.file != nil {
		_ = p.file.Close()
		p.file = nil
	}
}

func hashRunBundleProgram(file *os.File, size int64) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, maxRunBundleProgramBytes+1))
	if err != nil || n != size || n > maxRunBundleProgramBytes {
		return "", ErrRunResult
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// runBundleProgramIsScript reports whether the opened program starts with the
// kernel shebang magic "#!". Only the two-byte header is read and the file
// offset is restored, so the caller can still copy or execute the whole image.
func runBundleProgramIsScript(file *os.File) (bool, error) {
	var header [2]byte
	n, err := io.ReadFull(file, header[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false, err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	return n == 2 && header[0] == '#' && header[1] == '!', nil
}

// CheckRunBundleProgramPinPreflight applies the cheap, caller-visible part of
// the Linux pin policy before a caller sends a desktop request, opens an owner
// prompt or starts a child. When an expected digest is present the program must
// be a native executable image, not a shebang script: a pinned script is
// refused because a sealed snapshot would run under a descriptor path and the
// kernel would rewrite the script's $0, breaking relative assets and
// Node-style CLI package context.
//
// This check is advisory only. pinRunBundleProgram re-reads the same header and
// is the authoritative refusal, so a path that changes after this call is still
// fail-closed. Read failures are deliberately left to that later check instead
// of being reported as a policy refusal, and an empty digest is the explicit
// unpinned scope, which executes the original path and needs no header check.
func CheckRunBundleProgramPinPreflight(program string, expectedSHA256 string) error {
	if expectedSHA256 == "" {
		return nil
	}
	file, err := os.Open(program)
	if err != nil {
		return nil
	}
	defer file.Close()
	script, err := runBundleProgramIsScript(file)
	if err != nil || !script {
		return nil
	}
	return ErrRunProgramScriptPinUnsupported
}

// pinRunBundleProgram opens the program once, copies the bounded bytes into an
// anonymous memfd, verifies the copy against the expected digest when one is
// supplied, then seals the memfd against further writes, growth, shrink and
// truncation. This is an exact-byte snapshot, not merely an inode pin: an
// in-place overwrite of the original path after this point cannot affect the
// child. A short re-stat of the source also catches a concurrent mutation during
// the copy; a caller that supplied a digest gets the stronger whole-image check.
//
// Only a native executable image may be snapshotted this way. A shebang script
// is refused with ErrRunProgramScriptPinUnsupported before any memfd exists:
// executing the sealed copy through /proc/self/fd makes the kernel pass the
// descriptor path as the script's $0, silently changing relative-asset and
// package-context semantics. There is no shell or interpreter wrapper here.
func pinRunBundleProgram(program string, expectedSHA256 string) (*runBundlePinnedProgram, error) {
	source, err := os.Open(program)
	if err != nil {
		return nil, ErrRunResult
	}
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxRunBundleProgramBytes ||
		info.Mode().Perm()&0o111 == 0 {
		_ = source.Close()
		return nil, ErrRunResult
	}
	script, err := runBundleProgramIsScript(source)
	if err != nil {
		_ = source.Close()
		return nil, ErrRunResult
	}
	if script {
		_ = source.Close()
		return nil, ErrRunProgramScriptPinUnsupported
	}
	fd, err := unix.MemfdCreate("locklark-run-program", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		_ = source.Close()
		return nil, ErrRunResult
	}
	pinned := &runBundlePinnedProgram{file: os.NewFile(uintptr(fd), "locklark-run-program")}
	if pinned.file == nil {
		_ = unix.Close(fd)
		_ = source.Close()
		return nil, ErrRunResult
	}
	n, err := io.Copy(pinned.file, io.LimitReader(source, maxRunBundleProgramBytes+1))
	after, statErr := source.Stat()
	closeErr := source.Close()
	if err != nil || statErr != nil || closeErr != nil || n != info.Size() || n > maxRunBundleProgramBytes ||
		!os.SameFile(info, after) || after.Mode() != info.Mode() || after.Size() != info.Size() ||
		!after.ModTime().Equal(info.ModTime()) {
		pinned.close()
		return nil, ErrRunResult
	}
	if expectedSHA256 != "" {
		digest, err := hashRunBundleProgram(pinned.file, n)
		if err != nil || digest != expectedSHA256 {
			pinned.close()
			return nil, ErrRunResult
		}
	}
	// Seal only after the copy and optional digest check: F_SEAL_WRITE also
	// prevents truncation, F_SEAL_GROW and F_SEAL_SHRINK freeze the length, and
	// F_SEAL_SEAL makes the seal set final. The inherited descriptor therefore
	// names immutable bytes for the child's lifetime.
	if _, err := unix.FcntlInt(pinned.file.Fd(), unix.F_ADD_SEALS,
		unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		pinned.close()
		return nil, ErrRunResult
	}
	if _, err := pinned.file.Seek(0, io.SeekStart); err != nil {
		pinned.close()
		return nil, ErrRunResult
	}
	return pinned, nil
}

// newRunBundleCommand returns a command for the requested program and owns the
// program snapshot until the caller's cleanup runs. stdio, env, working
// directory and the deadline context stay owned by the caller.
//
// With a non-empty expected digest the program must be a native executable and
// is executed from the sealed memfd through /proc/self/fd, so a later rename,
// truncate or in-place write cannot change the executed bytes. argv0 is the
// approved program path for such an image; pinning is refused for shebang
// scripts because the kernel would replace their $0 with the descriptor path.
//
// With an empty expected digest the original path is executed directly. This
// is the explicit unpinned scope: it preserves the original $0, relative-asset
// and package-resolution semantics of scripts, makes no memfd copy, and is not
// an exact-byte pin. Any open or snapshot error still fails closed; there is no
// shell or eval wrapper and no mutable path fallback.
func newRunBundleCommand(ctx context.Context, program string, args []string, expectedSHA256 string) (*exec.Cmd, func(), error) {
	if expectedSHA256 == "" {
		info, err := os.Stat(program)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Mode().Perm()&0o111 == 0 {
			return nil, nil, ErrRunResult
		}
		return exec.CommandContext(ctx, program, args...), func() {}, nil
	}
	pinned, err := pinRunBundleProgram(program, expectedSHA256)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.CommandContext(ctx, program, args...)
	// ExtraFiles[0] becomes fd 3 in the child with close-on-exec cleared. The
	// child's execve("/proc/self/fd/3") therefore executes exactly this sealed
	// snapshot, independent of what the caller-visible path now names. Only a
	// native executable reaches this branch; a shebang script was refused
	// above so its $0 is never rewritten to this descriptor path.
	cmd.Path = "/proc/self/fd/3"
	cmd.ExtraFiles = []*os.File{pinned.file}
	return cmd, pinned.close, nil
}
