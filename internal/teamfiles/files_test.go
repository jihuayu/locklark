package teamfiles

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestTransferFailedPublicationDoesNotClaimSuccessOrRemoveCompleteFinal(t *testing.T) {
	for _, published := range []bool{false, true} {
		parent := t.TempDir()
		path := filepath.Join(parent, "transfer.json")
		raw := []byte("complete public encrypted artifact")
		hooks := localWriteHooks{}
		if published {
			// The final link is visible when this seam runs; the injected
			// failure must still clean the owned stage and leave a one-link
			// final file.
			hooks.afterPublish = func() error { return errors.New("injected publication failure") }
		} else {
			hooks.beforeLink = func() error { return errors.New("injected publication failure") }
		}
		err := writeNew(path, raw, hooks)
		if published {
			observed, readErr := Read(path, 1024, true)
			if !errors.Is(err, ErrPublicationUnknown) || readErr != nil || !bytes.Equal(observed, raw) {
				t.Fatal("uncertain publication lost complete final or claimed success")
			}
		} else {
			if !errors.Is(err, ErrFile) {
				t.Fatal("pre-publication failure classification incorrect")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("failed publication exposed final name")
			}
		}
		entries, readErr := os.ReadDir(parent)
		expected := 0
		if published {
			expected = 1
		}
		if readErr != nil || len(entries) != expected {
			t.Fatal("failed publication retained owned temporary file")
		}
	}
}

func TestTransferStrictJSON(t *testing.T) {
	type record struct {
		Version int `json:"version"`
	}
	for _, raw := range []string{"{\"version\":1}", "{ \"version\" : 1 }\n"} {
		var value record
		if JSON([]byte(raw), &value) != nil || value.Version != 1 {
			t.Fatal("valid public record refused")
		}
	}
	for _, raw := range [][]byte{[]byte("{\"version\":1,\"version\":2}"), []byte("{\"version\":1,\"Version\":2}"), []byte("{\"version\":1,\"seed\":\"private-canary\"}"), []byte("{\"version\":1}{}"), {0xff}, []byte(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18))} {
		var value record
		if JSON(raw, &value) == nil {
			t.Fatal("ambiguous or unsupported public record accepted")
		}
	}
}
func TestTransferNoOverwriteAndConcurrentSingleWinner(t *testing.T) {
	parent := t.TempDir()
	if os.Chmod(parent, 0700) != nil {
		t.Fatal("private parent setup")
	}
	path := filepath.Join(parent, "transfer.json")
	const workers = 8
	start := make(chan struct{})
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); <-start; errs[i] = WriteNew(path, []byte{byte('a' + i)}) }(i)
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, err := range errs {
		if err == nil {
			if winner >= 0 {
				t.Fatal("multiple transfer publishers")
			}
			winner = i
		}
	}
	raw, err := Read(path, 1024, true)
	if winner < 0 || err != nil || !bytes.Equal(raw, []byte{byte('a' + winner)}) {
		t.Fatal("complete sole winning transfer not preserved")
	}
	if WriteNew(path, []byte("replacement")) == nil {
		t.Fatal("existing transfer overwritten")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatal("transfer temporary files retained")
	}
	if _, err := Read(path, 0, true); err == nil {
		t.Fatal("invalid read bound accepted")
	}
}
func TestTransferBoundedReadAndOwnedCleanup(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "record")
	if WriteNew(path, []byte("complete public transfer")) != nil {
		t.Fatal("transfer setup")
	}
	if _, err := Read(path, 3, true); err == nil {
		t.Fatal("oversized transfer accepted")
	}
	tmp := filepath.Join(parent, "temporary")
	f, err := createLocalFile(tmp)
	if err != nil {
		t.Fatal("temporary setup")
	}
	owned, err := f.Stat()
	f.Close()
	if err != nil {
		t.Fatal("temporary identity")
	}
	if os.Rename(tmp, tmp+"-moved") != nil || os.WriteFile(tmp, []byte("replacement"), 0600) != nil {
		t.Fatal("temporary replacement setup")
	}
	if removeOwned(tmp, owned) == nil {
		t.Fatal("cleanup accepted replacement")
	}
	raw, err := os.ReadFile(tmp)
	if err != nil || string(raw) != "replacement" {
		t.Fatal("cleanup removed another file")
	}
	if Distinct(path, path) || Distinct(path, filepath.Join(parent, ".", "record")) {
		t.Fatal("path alias accepted")
	}
}

func TestTransferExplicitBoundedHelperDoesNotWidenExistingLimits(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "custody-artifact")
	raw := bytes.Repeat([]byte{0x5a}, 17<<20)
	defer clear(raw)
	if err := WriteNew(path, raw); !errors.Is(err, ErrFile) {
		t.Fatal("existing write limit was widened")
	}
	if err := WriteNewLimited(context.Background(), path, raw, 32<<20); err != nil {
		t.Fatal("explicit bounded write refused a supported size")
	}
	got, err := ReadLimited(context.Background(), path, 32<<20, true)
	if err != nil || !bytes.Equal(got, raw) {
		clear(got)
		t.Fatal("explicit bounded read did not return the exact bytes")
	}
	clear(got)
	if err := WriteNewLimited(context.Background(), filepath.Join(parent, "too-small"), raw, 16<<20); !errors.Is(err, ErrFile) {
		t.Fatal("explicit bound was not enforced")
	}
	if _, err := ReadLimited(context.Background(), path, maxBoundedFileBytes+1, true); !errors.Is(err, ErrFile) {
		t.Fatal("explicit read bound exceeded the fixed maximum")
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := filepath.Join(parent, "cancelled")
	if err := WriteNewLimited(cancelCtx, cancelled, raw[:1024], 1024); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-publication cancellation was not reported")
	}
	if _, err := os.Lstat(cancelled); !os.IsNotExist(err) {
		t.Fatal("pre-publication cancellation exposed a final name")
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 1 {
		t.Fatal("bounded helper retained a temporary file")
	}
}

func TestBoundedWriteCancellationAfterVisibilityIsUnknown(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "custody-artifact")
	raw := []byte("complete encrypted custody artifact")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := writeNewLimited(ctx, path, raw, 1024, localWriteHooks{
		afterPublish: func() error {
			cancel()
			return nil
		},
	})
	if !errors.Is(err, ErrPublicationUnknown) {
		t.Fatal("post-visibility cancellation claimed a definite outcome")
	}
	got, readErr := Read(path, 1024, true)
	if readErr != nil || !bytes.Equal(got, raw) {
		clear(got)
		t.Fatal("post-visibility cancellation did not preserve the complete final file")
	}
	clear(got)
	if entries, readErr := os.ReadDir(parent); readErr != nil || len(entries) != 1 {
		t.Fatal("post-visibility cancellation retained a temporary file")
	}
}
