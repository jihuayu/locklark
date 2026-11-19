//go:build windows

package teamfiles

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// assertWindowsRenameBuffer checks the exact aligned FILE_RENAME_INFORMATION
// offsets and the documented minimum bounded allocation, not just a successful
// syscall. The filename is encoded as UTF-16, including a surrogate pair for
// the supplementary case, and the declared length excludes its terminator.
func assertWindowsRenameBuffer(t *testing.T, buffer []byte, name16 []uint16, parent windows.Handle, name string) {
	t.Helper()
	var layout windowsRenameInformation
	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	wantRootOffset := ptrSize
	wantLengthOffset := 2 * ptrSize
	wantHeader := 2*ptrSize + 4
	wantSize := wantHeader + 2
	if remainder := wantSize % ptrSize; remainder != 0 {
		wantSize += ptrSize - remainder
	}
	if got := int(unsafe.Offsetof(layout.RootDirectory)); got != wantRootOffset {
		t.Fatalf("RootDirectory offset = %d, want %d", got, wantRootOffset)
	}
	if got := int(unsafe.Offsetof(layout.FileNameLength)); got != wantLengthOffset {
		t.Fatalf("FileNameLength offset = %d, want %d", got, wantLengthOffset)
	}
	if got := int(unsafe.Offsetof(layout.FileName)); got != wantHeader {
		t.Fatalf("FileName offset = %d, want %d", got, wantHeader)
	}
	if got := int(unsafe.Sizeof(layout)); got != wantSize {
		t.Fatalf("sizeof layout = %d, want %d", got, wantSize)
	}
	if len(name16) < 2 {
		t.Fatal("UTF-16 basename has no terminator")
	}
	wantEncoded := utf16.Encode([]rune(name))
	if !slices.Equal(name16[:len(name16)-1], wantEncoded) || name16[len(name16)-1] != 0 {
		t.Fatal("UTF-16 basename does not have the exact expected code units")
	}
	if minimum := wantSize + (len(name16)-1)*2; len(buffer) < minimum {
		t.Fatalf("buffer length = %d, below sizeof+FileNameLength minimum %d", len(buffer), minimum)
	}
	if len(buffer) != wantSize+len(name16)*2 {
		t.Fatalf("buffer length = %d, want sizeof+encoded-with-terminator = %d",
			len(buffer), wantSize+len(name16)*2)
	}
	if buffer[0] != 0 {
		t.Fatal("ReplaceIfExists was not false")
	}
	if got := *(*windows.Handle)(unsafe.Pointer(&buffer[wantRootOffset])); got != parent {
		t.Fatal("RootDirectory does not name the exact held parent handle")
	}
	if got := *(*uint32)(unsafe.Pointer(&buffer[wantLengthOffset])); got != uint32((len(name16)-1)*2) {
		t.Fatalf("FileNameLength = %d, want %d (terminator excluded)", got, (len(name16)-1)*2)
	}
	wantBytes := unsafe.Slice((*byte)(unsafe.Pointer(&name16[0])), len(name16)*2)
	if !bytes.Equal(buffer[wantHeader:wantHeader+len(wantBytes)], wantBytes) {
		t.Fatal("FileName bytes are not the exact UTF-16 encoding")
	}
}

func writeWindowsTestFile(t *testing.T, parent *windowsParent, staging string, raw []byte) *os.File {
	t.Helper()
	f, err := createWindowsOwnedFileAt(parent.handle, staging)
	if err != nil {
		t.Fatal("owned staging creation failed")
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) {
		_ = f.Close()
		t.Fatal("owned staging write failed")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatal("owned staging sync failed")
	}
	if err := verifyWindowsHandle(f, true, 1); err != nil {
		_ = f.Close()
		t.Fatal("owned staging is not private with one link")
	}
	return f
}

func TestWindowsWriteNewCancellationAtFinalPrepublicationBoundary(t *testing.T) {
	dir := t.TempDir()
	sibling := filepath.Join(dir, "protected-sibling")
	siblingRaw := []byte("protected sibling must stay unchanged")
	if err := os.WriteFile(sibling, siblingRaw, 0600); err != nil {
		t.Fatal("CANCEL_BOUNDARY_SIBLING_FIXTURE_FAILED")
	}
	path := filepath.Join(dir, "artifact-\U0001f600")
	raw := []byte{0x00, 0x01, 0xfe, 0xff, 'e', 'x', 'a', 'c', 't'}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reached := false
	err := writeNewLimited(ctx, path, raw, 1024, localWriteHooks{
		beforeCommit: func() error {
			reached = true
			cancel()
			return nil
		},
	})
	if !reached {
		t.Fatal("CANCEL_BOUNDARY_HOOK_NOT_REACHED")
	}
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrPublicationUnknown) {
		t.Fatal("FINAL_BOUNDARY_CANCEL_NOT_REFUSED_BEFORE_PUBLISH")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("FINAL_BOUNDARY_CANCEL_LEFT_FINAL_ENTRY")
	}
	got, err := os.ReadFile(sibling)
	if err != nil || !bytes.Equal(got, siblingRaw) {
		clear(got)
		t.Fatal("FINAL_BOUNDARY_CANCEL_CHANGED_PROTECTED_SIBLING")
	}
	clear(got)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(sibling) {
		t.Fatal("FINAL_BOUNDARY_CANCEL_RETAINED_STAGING_OR_FINAL")
	}
}

func TestWindowsRenameNoReplaceUnicodeAndHeldParent(t *testing.T) {
	cases := []struct {
		label string
		name  string
		raw   []byte
	}{
		{"single-unit", "custody-\u00e9", []byte("single-unit exact custody bytes")},
		{"supplementary", "custody-\U0001f600", []byte("supplementary exact custody bytes")},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			dir := t.TempDir()
			parent, err := openWindowsParent(dir)
			if err != nil {
				t.Fatal("held parent could not be opened")
			}
			defer parent.Close()
			staging := ".locklark-team-transfer-" + tc.label
			f := writeWindowsTestFile(t, parent, staging, tc.raw)
			defer f.Close()
			owned, err := f.Stat()
			if err != nil {
				t.Fatal("staging identity unavailable")
			}
			buffer, name16, err := windowsRenameBuffer(parent.handle, tc.name)
			if err != nil {
				t.Fatal("rename buffer construction failed")
			}
			assertWindowsRenameBuffer(t, buffer, name16, parent.handle, tc.name)
			if err := renameWindowsNoReplace(windows.Handle(f.Fd()), parent.handle, tc.name); err != nil {
				t.Fatalf("handle-relative rename failed: %v", err)
			}
			after, err := f.Stat()
			if err != nil || !os.SameFile(owned, after) {
				t.Fatal("post-rename handle no longer identifies the staged inode")
			}
			if err := f.Sync(); err != nil {
				t.Fatal("post-rename handle flush failed")
			}
			if err := verifyWindowsHandle(f, true, 1); err != nil {
				t.Fatal("post-rename handle is not private with one link")
			}
			if _, err := lstatWindowsAt(parent.handle, staging); !windowsNotFound(err) {
				t.Fatal("staging name remained after handle-relative rename")
			}
			final, err := lstatWindowsAt(parent.handle, tc.name)
			if err != nil || !os.SameFile(owned, final) {
				t.Fatal("final name is not the staging inode")
			}
			if err := parent.verifyFile(tc.name, owned, true, 1); err != nil {
				t.Fatal("final name failed private ACL or link-count verification")
			}
			got, err := Read(filepath.Join(dir, tc.name), 1024, true)
			if err != nil || !bytes.Equal(got, tc.raw) {
				clear(got)
				t.Fatal("normal Read did not return exact renamed bytes")
			}
			clear(got)
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != tc.name {
				t.Fatal("held-parent rename left hidden temporary data")
			}
			if err := f.Close(); err != nil {
				t.Fatal("final handle close failed")
			}
			if err := parent.removeOwned(tc.name, owned, 1); err != nil {
				t.Fatal("owned final cleanup failed")
			}
			entries, err = os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("owned final cleanup left a name behind")
			}
		})
	}
}

func TestWindowsRenameNoReplaceRefusesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	parent, err := openWindowsParent(dir)
	if err != nil {
		t.Fatal("held parent could not be opened")
	}
	defer parent.Close()
	firstRaw := []byte("first complete protected artifact")
	first := writeWindowsTestFile(t, parent, ".locklark-team-transfer-first", firstRaw)
	defer first.Close()
	firstOwned, err := first.Stat()
	if err != nil {
		t.Fatal("first staging identity unavailable")
	}
	if err := renameWindowsNoReplace(windows.Handle(first.Fd()), parent.handle, "target"); err != nil {
		t.Fatalf("first handle-relative rename failed: %v", err)
	}
	secondRaw := []byte("second must not replace the first")
	second := writeWindowsTestFile(t, parent, ".locklark-team-transfer-second", secondRaw)
	defer second.Close()
	secondOwned, err := second.Stat()
	if err != nil {
		t.Fatal("second staging identity unavailable")
	}
	// Call the syscall primitive directly. writeNewAtPath preflight would
	// refuse an existing target before reaching this no-replace argument.
	if err := renameWindowsNoReplace(windows.Handle(second.Fd()), parent.handle, "target"); err == nil {
		t.Fatal("direct no-replace rename replaced an existing target")
	}
	final, err := lstatWindowsAt(parent.handle, "target")
	if err != nil || !os.SameFile(firstOwned, final) {
		t.Fatal("failed no-replace rename changed the target identity")
	}
	if err := parent.verifyFile("target", firstOwned, true, 1); err != nil {
		t.Fatal("target lost private ACL or one-link identity")
	}
	kept, err := lstatWindowsAt(parent.handle, ".locklark-team-transfer-second")
	if err != nil || !os.SameFile(secondOwned, kept) {
		t.Fatal("failed no-replace rename lost the second staging inode")
	}
	if err := verifyWindowsHandle(second, true, 1); err != nil {
		t.Fatal("second staging lost private ACL or one-link identity")
	}
	got, err := Read(filepath.Join(dir, "target"), 1024, true)
	if err != nil || !bytes.Equal(got, firstRaw) {
		clear(got)
		t.Fatal("failed no-replace rename did not preserve exact target bytes")
	}
	clear(got)
	if err := WriteNew(filepath.Join(dir, "target"), []byte("replacement")); !errors.Is(err, ErrFile) {
		t.Fatal("normal no-replace API accepted an existing target")
	}
	got, err = Read(filepath.Join(dir, "target"), 1024, true)
	if err != nil || !bytes.Equal(got, firstRaw) {
		clear(got)
		t.Fatal("normal no-replace API changed exact target bytes")
	}
	clear(got)
	if err := first.Close(); err != nil {
		t.Fatal("first handle close failed")
	}
	if err := second.Close(); err != nil {
		t.Fatal("second handle close failed")
	}
	if err := parent.removeOwned("target", firstOwned, 1); err != nil {
		t.Fatal("owned target cleanup failed")
	}
	if err := parent.removeOwned(".locklark-team-transfer-second", secondOwned, 1); err != nil {
		t.Fatal("owned second staging cleanup failed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("no-replace fixture retained temporary data")
	}
}

func TestWindowsWriteNewVerifiedDifferentFinalAfterFailedRenameIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	incumbentRaw := []byte("verified incumbent must remain unchanged")
	raw := []byte{0x00, 0x01, 0xfe, 0xff, 'e', 'x', 'a', 'c', 't'}
	var setupErr error
	err := writeNew(path, raw, localWriteHooks{
		beforeCommit: func() error {
			setupErr = os.WriteFile(path, incumbentRaw, 0600)
			return setupErr
		},
	})
	if setupErr != nil {
		t.Fatal("VERIFIED_DIFFERENT_FINAL_FIXTURE_FAILED")
	}
	if !errors.Is(err, ErrFile) || errors.Is(err, ErrPublicationUnknown) {
		t.Fatal("VERIFIED_DIFFERENT_FINAL_WAS_NOT_A_DEFINITE_REFUSAL")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(got, incumbentRaw) {
		clear(got)
		t.Fatal("VERIFIED_DIFFERENT_FINAL_CHANGED_THE_INCUMBENT")
	}
	clear(got)
	entries, readErr := os.ReadDir(dir)
	if readErr != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatal("VERIFIED_DIFFERENT_FINAL_RETAINED_STAGING_OR_EXTRA_ENTRY")
	}
}

func TestWindowsWriteNewInconclusiveFinalProbeAfterFailedRenameIsUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	incumbentRaw := []byte("incumbent must remain unchanged")
	raw := []byte{0x00, 0x01, 0xfe, 0xff, 'e', 'x', 'a', 'c', 't'}
	// The seam runs only inside the failed-rename branch, so observing it also
	// proves the real kernel no-replace rename rejected the real incumbent.
	probeReached := false
	err := writeNew(path, raw, localWriteHooks{
		beforeCommit: func() error {
			// Create a real different incumbent after the destination checks
			// but before the no-replace rename. The kernel must reject the
			// existing target rather than replacing it.
			return os.WriteFile(path, incumbentRaw, 0600)
		},
		failedRenameFinalProbe: func() error {
			probeReached = true
			return windows.STATUS_ACCESS_DENIED
		},
	})
	if !probeReached {
		t.Fatal("INCONCLUSIVE_FINAL_PROBE_SEAM_NOT_REACHED_AFTER_RENAME_REJECTION")
	}
	if err != ErrPublicationUnknown {
		t.Fatal("INCONCLUSIVE_FINAL_PROBE_WAS_NOT_EXACT_UNKNOWN")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(got, incumbentRaw) {
		clear(got)
		t.Fatal("INCONCLUSIVE_FINAL_PROBE_CHANGED_THE_INCUMBENT")
	}
	clear(got)
	entries, readErr := os.ReadDir(dir)
	if readErr != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatal("INCONCLUSIVE_FINAL_PROBE_RETAINED_STAGING_OR_EXTRA_ENTRY")
	}
	if err := WriteNew(path, []byte("replacement")); !errors.Is(err, ErrFile) {
		t.Fatal("INCONCLUSIVE_OUTCOME_PERMITTED_OVERWRITE")
	}
	got, readErr = os.ReadFile(path)
	if readErr != nil || !bytes.Equal(got, incumbentRaw) {
		clear(got)
		t.Fatal("INCONCLUSIVE_OUTCOME_INCUMBENT_CHANGED_AFTER_RETRY")
	}
	clear(got)
}

func TestWindowsWriteNewPostRenameFailureIsUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact-\U0001f600")
	raw := []byte{0x00, 0x01, 0xfe, 0xff, 'e', 'x', 'a', 'c', 't'}
	err := writeNew(path, raw, localWriteHooks{
		afterLink: func() error { return errors.New("injected post-rename flush failure") },
	})
	if !errors.Is(err, ErrPublicationUnknown) {
		t.Fatal("post-rename failure did not return exact Unknown")
	}
	got, readErr := Read(path, 1024, true)
	if readErr != nil || !bytes.Equal(got, raw) {
		clear(got)
		t.Fatal("Unknown outcome did not preserve exact visible final bytes")
	}
	clear(got)
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.Mode().IsRegular() {
		t.Fatal("Unknown outcome removed the visible final name")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("Unknown outcome final could not be reopened")
	}
	if err := verifyWindowsHandle(f, true, 1); err != nil {
		_ = f.Close()
		t.Fatal("Unknown outcome final lost private ACL or one-link identity")
	}
	opened, err := f.Stat()
	closeErr := f.Close()
	if err != nil || closeErr != nil || !os.SameFile(info, opened) {
		t.Fatal("Unknown outcome final identity changed across reopen")
	}
	if err := WriteNew(path, []byte("replacement")); !errors.Is(err, ErrFile) {
		t.Fatal("Unknown outcome final was overwritten")
	}
	got, err = Read(path, 1024, true)
	if err != nil || !bytes.Equal(got, raw) {
		clear(got)
		t.Fatal("Unknown outcome final bytes changed after a subsequent write attempt")
	}
	clear(got)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatal("post-rename Unknown retained a temporary file")
	}
}
