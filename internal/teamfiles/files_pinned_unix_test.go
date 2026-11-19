//go:build unix

package teamfiles

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestWriteNewCancellationAtFinalPrepublicationBoundary(t *testing.T) {
	root := t.TempDir()
	sibling := filepath.Join(root, "protected-sibling")
	siblingRaw := []byte("protected sibling must stay unchanged")
	if err := os.WriteFile(sibling, siblingRaw, 0600); err != nil {
		t.Fatal("CANCEL_BOUNDARY_SIBLING_FIXTURE_FAILED")
	}
	path := filepath.Join(root, "artifact")
	raw := []byte("cancelled artifact must never be published")
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
	assertNoTemporary(t, root, filepath.Base(sibling))
}

func TestWriteNewInconclusiveFinalProbeAfterFailedLinkIsUnknown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory access denial used to make the final-name probe inconclusive")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal("INCONCLUSIVE_LINK_FIXTURE_FAILED")
	}
	path := filepath.Join(parent, "artifact")
	sibling := filepath.Join(parent, "protected-sibling")
	siblingRaw := []byte("protected sibling must stay unchanged")
	if err := os.WriteFile(sibling, siblingRaw, 0600); err != nil {
		t.Fatal("INCONCLUSIVE_LINK_SIBLING_FAILED")
	}
	raw := []byte("failed link must not claim a definite outcome")
	restored := false
	restore := func() {
		if !restored {
			_ = os.Chmod(parent, 0700)
			restored = true
		}
	}
	defer restore()
	// Remove directory search permission at the last pre-publication seam. The
	// real linkat and statat calls relative to the held parent then both fail
	// with access denial, so the final-name probe is not a verified absence.
	err := writeNew(path, raw, localWriteHooks{
		beforeCommit: func() error { return os.Chmod(parent, 0000) },
	})
	restore()
	if !errors.Is(err, ErrPublicationUnknown) {
		t.Fatal("INCONCLUSIVE_FINAL_PROBE_WAS_NOT_UNKNOWN")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("INCONCLUSIVE_FINAL_PROBE_LEFT_A_FINAL_NAME")
	}
	got, err := os.ReadFile(sibling)
	if err != nil || !bytes.Equal(got, siblingRaw) {
		clear(got)
		t.Fatal("INCONCLUSIVE_FINAL_PROBE_CHANGED_PROTECTED_SIBLING")
	}
	clear(got)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal("INCONCLUSIVE_FINAL_PROBE_DIR_UNAVAILABLE")
	}
	staging := 0
	for _, entry := range entries {
		switch {
		case entry.Name() == filepath.Base(sibling):
		case strings.HasPrefix(entry.Name(), ".locklark-team-transfer-"):
			staging++
		default:
			t.Fatal("INCONCLUSIVE_FINAL_PROBE_RETAINED_UNEXPECTED_ENTRY")
		}
	}
	if staging != 1 {
		t.Fatal("INCONCLUSIVE_FINAL_PROBE_DID_NOT_RETAIN_ONLY_SAFE_STAGING")
	}
}

func TestWriteNewRefusesParentInterchangeBeforePublish(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	moved := filepath.Join(root, "moved")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal("PARENT_INTERCHANGE_FIXTURE_FAILED")
	}
	path := filepath.Join(parent, "artifact")
	var swapErr error
	err := writeNew(path, []byte("complete artifact"), localWriteHooks{
		beforeLink: func() error {
			if swapErr = os.Rename(parent, moved); swapErr != nil {
				return swapErr
			}
			swapErr = os.Mkdir(parent, 0700)
			return swapErr
		},
	})
	if swapErr != nil {
		t.Fatal("PARENT_INTERCHANGE_SWAP_FAILED")
	}
	if !errors.Is(err, ErrFile) {
		t.Fatal("PARENT_INTERCHANGE_WAS_NOT_REFUSED")
	}
	for _, dir := range []string{moved, parent} {
		if _, err := os.Lstat(filepath.Join(dir, "artifact")); !os.IsNotExist(err) {
			t.Fatal("PARENT_INTERCHANGE_PUBLISHED_ON_WRONG_PARENT")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatal("PARENT_INTERCHANGE_RETAINED_OWNED_TEMP")
		}
	}
}

func TestWriteNewDurableOrderAndFinalSyncUnknown(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact")
	raw := []byte("complete encrypted custody artifact")
	var events []string
	err := writeNew(path, raw, localWriteHooks{
		afterLink:      func() error { events = append(events, "final-link"); return nil },
		afterPublish:   func() error { events = append(events, "final-sync"); return nil },
		afterUnlink:    func() error { events = append(events, "temp-unlink"); return nil },
		afterFinalSync: func() error { events = append(events, "cleanup-sync"); return nil },
	})
	if err != nil {
		t.Fatal("DURABLE_ORDER_WRITE_FAILED")
	}
	want := []string{"final-link", "final-sync", "temp-unlink", "cleanup-sync"}
	if !reflect.DeepEqual(events, want) {
		t.Fatal("DURABLE_ORDER_NOT_FINAL_LINK_FSYNC_UNLINK_FSYNC")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("DURABLE_ORDER_FINAL_MISSING")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		t.Fatal("DURABLE_ORDER_NOT_ONE_LINK")
	}
	assertNoTemporary(t, root, filepath.Base(path))

	failDir := filepath.Join(root, "final-sync-failure")
	if err := os.Mkdir(failDir, 0700); err != nil {
		t.Fatal("FINAL_SYNC_FAILURE_DIR_FAILED")
	}
	failPath := filepath.Join(failDir, "artifact")
	injected := errors.New("injected final parent sync failure")
	err = writeNew(failPath, raw, localWriteHooks{
		beforeFinalSync: func() error { return injected },
	})
	if !errors.Is(err, ErrPublicationUnknown) {
		t.Fatal("FINAL_SYNC_FAILURE_NOT_UNKNOWN")
	}
	failed, err := os.ReadFile(failPath)
	if err != nil || !bytes.Equal(failed, raw) {
		clear(failed)
		t.Fatal("FINAL_SYNC_FAILURE_DID_NOT_PRESERVE_COMPLETE_FINAL")
	}
	clear(failed)
	info, err = os.Lstat(failPath)
	if err != nil {
		t.Fatal("FINAL_SYNC_FAILURE_FINAL_MISSING")
	}
	stat, ok = info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		t.Fatal("FINAL_SYNC_FAILURE_NOT_ONE_LINK")
	}
	assertNoTemporary(t, failDir, filepath.Base(failPath))
}

func TestWriteNewFirstFailureAfterFinalLinkCleansOwnedStage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact")
	raw := []byte("first failure after final link")
	err := writeNew(path, raw, localWriteHooks{
		afterLink: func() error { return errors.New("injected after final link") },
	})
	if !errors.Is(err, ErrPublicationUnknown) {
		t.Fatal("FIRST_FINAL_LINK_FAILURE_NOT_UNKNOWN")
	}
	got, readErr := Read(path, 1024, true)
	if readErr != nil || !bytes.Equal(got, raw) {
		clear(got)
		t.Fatal("FIRST_FINAL_LINK_FAILURE_NOT_REOPENABLE")
	}
	clear(got)
	info, statErr := os.Lstat(path)
	if statErr != nil {
		t.Fatal("FIRST_FINAL_LINK_FAILURE_FINAL_MISSING")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		t.Fatal("FIRST_FINAL_LINK_FAILURE_LEFT_EXTRA_LINK")
	}
	assertNoTemporary(t, root, filepath.Base(path))
}

func TestWriteNewUnknownAfterSafeOwnedUnlinkCanReopen(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact")
	raw := []byte("unknown after safe owned unlink")
	err := writeNew(path, raw, localWriteHooks{
		beforeFinalSync: func() error { return errors.New("injected final sync failure") },
	})
	if !errors.Is(err, ErrPublicationUnknown) {
		t.Fatal("SAFE_UNLINK_SYNC_FAILURE_NOT_UNKNOWN")
	}
	got, readErr := Read(path, 1024, true)
	if readErr != nil || !bytes.Equal(got, raw) {
		clear(got)
		t.Fatal("SAFE_UNLINK_SYNC_FAILURE_NOT_REOPENABLE")
	}
	clear(got)
	info, statErr := os.Lstat(path)
	if statErr != nil {
		t.Fatal("SAFE_UNLINK_SYNC_FAILURE_FINAL_MISSING")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		t.Fatal("SAFE_UNLINK_SYNC_FAILURE_LEFT_EXTRA_LINK")
	}
	assertNoTemporary(t, root, filepath.Base(path))
}

func TestWriteNewCleanupFailureRefusesReopenAndExtraLink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact")
	external := filepath.Join(root, "external")
	raw := []byte("cleanup failure must not be salvaged")
	err := writeNew(path, raw, localWriteHooks{
		afterLink: func() error { return os.Link(path, external) },
	})
	if !errors.Is(err, ErrPublicationUnknown) {
		t.Fatal("CLEANUP_FAILURE_NOT_UNKNOWN")
	}
	if got, readErr := Read(path, 1024, true); !errors.Is(readErr, ErrFile) {
		clear(got)
		t.Fatal("CLEANUP_FAILURE_REOPEN_ACCEPTED_EXTRA_LINK")
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		t.Fatal("CLEANUP_FAILURE_FINAL_MISSING")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 3 {
		t.Fatal("CLEANUP_FAILURE_REMOVED_OR_SALVAGED_EXTRA_LINK")
	}
	if _, statErr := os.Lstat(external); statErr != nil || stat.Nlink != 3 {
		t.Fatal("CLEANUP_FAILURE_REMOVED_OTHER_LINK")
	}
}

func TestReadLimitedRefusesSubstitutedParent(t *testing.T) {
	raw := []byte("exact bounded custody bytes")
	for _, at := range []string{"AFTER_CAPTURE", "AFTER_OPEN"} {
		t.Run(at, func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "parent")
			moved := filepath.Join(root, "moved")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal("READ_PARENT_FIXTURE_FAILED")
			}
			path := filepath.Join(parent, "artifact")
			if err := WriteNew(path, raw); err != nil {
				t.Fatal("READ_PARENT_WRITE_FAILED")
			}
			swap := func() error {
				if err := os.Rename(parent, moved); err != nil {
					return err
				}
				if err := os.Mkdir(parent, 0700); err != nil {
					return err
				}
				return os.WriteFile(path, raw, 0600)
			}
			hooks := localReadHooks{}
			if at == "AFTER_CAPTURE" {
				hooks.afterCapture = swap
			} else {
				hooks.afterOpen = swap
			}
			got, err := readLimited(context.Background(), path, 1024, true,
				maxBoundedFileBytes, hooks)
			clear(got)
			if !errors.Is(err, ErrFile) {
				t.Fatal("SUBSTITUTED_PARENT_READ_NOT_REFUSED")
			}
		})
	}
}

func assertNoTemporary(t *testing.T, dir, final string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != final {
		t.Fatal("DURABLE_ORDER_RETAINED_TEMPORARY_OR_MISSING_FINAL")
	}
}
