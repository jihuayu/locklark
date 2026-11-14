package vaultfilepublish

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

var errVerifyRejected = errors.New("verifier rejected")

// readOnlyFakeBackend is a ReadBackend that records calls and returns a fixed
// result.
type readOnlyFakeBackend struct {
	calls  int
	gotCtx context.Context
	gotNam string
	result vaultfilebackend.ReadResult
	err    error
}

func (f *readOnlyFakeBackend) Read(ctx context.Context, name string) (vaultfilebackend.ReadResult, error) {
	f.calls++
	f.gotCtx = ctx
	f.gotNam = name
	return f.result, f.err
}

func mustResult(t *testing.T, data []byte, revision string) vaultfilebackend.ReadResult {
	t.Helper()
	return vaultfilebackend.ReadResult{Bytes: data, Revision: vaultfilebackend.Revision(revision)}
}

func TestReadPulledRequiresVerifier(t *testing.T) {
	backend := &readOnlyFakeBackend{result: mustResult(t, []byte("ciphertext"), `"etag-1"`)}

	got, err := ReadPulled(context.Background(), backend, "file.kdbx", nil)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ReadPulled with nil verifier: err = %v, want ErrInvalidArgument", err)
	}
	if backend.calls != 0 {
		t.Fatalf("ReadPulled with nil verifier performed %d backend reads, want 0", backend.calls)
	}
	if got.Revision() != "" || got.Bytes() != nil {
		t.Fatalf("ReadPulled with nil verifier returned non-zero Pulled: %+v", got)
	}
}

func TestReadPulledRejectsInvalidArguments(t *testing.T) {
	verifier := func(context.Context, []byte, vaultfilebackend.Revision) error { return nil }

	tests := []struct {
		name     string
		ctx      context.Context
		backend  ReadBackend
		fileName string
		verifier PullVerifier
		want     string
	}{
		{name: "nil context", ctx: nil, backend: &readOnlyFakeBackend{}, fileName: "f", verifier: verifier, want: "nil context"},
		{name: "nil backend", ctx: context.Background(), backend: nil, fileName: "f", verifier: verifier, want: "nil backend"},
		{name: "nil verifier", ctx: context.Background(), backend: &readOnlyFakeBackend{}, fileName: "f", verifier: nil, want: "nil verifier"},
		{name: "empty name", ctx: context.Background(), backend: &readOnlyFakeBackend{}, fileName: "", verifier: verifier, want: "empty name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadPulled(tt.ctx, tt.backend, tt.fileName, tt.verifier)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %q, want mention of %q", err, tt.want)
			}
			if fb, ok := tt.backend.(*readOnlyFakeBackend); ok && fb.calls != 0 {
				t.Fatalf("backend read %d times, want 0", fb.calls)
			}
		})
	}
}

func TestReadPulledPreservesBytesAndOpaqueRevision(t *testing.T) {
	data := []byte{0x00, 0xff, 0x10, 'v', 'a', 'u', 'l', 't', 0x0a}
	// A quoted ETag must survive verbatim, including the quotes and the W/ form.
	const revision = `W/"9a4c5b0f3e2d1c"`

	ctx := context.Background()
	backend := &readOnlyFakeBackend{result: mustResult(t, data, revision)}

	var verifiedBytes []byte
	var verifiedRevision vaultfilebackend.Revision
	verifier := func(vctx context.Context, got []byte, rev vaultfilebackend.Revision) error {
		if vctx != ctx {
			t.Errorf("verifier ctx = %v, want the caller ctx", vctx)
		}
		verifiedBytes = append([]byte(nil), got...)
		verifiedRevision = rev
		return nil
	}

	pulled, err := ReadPulled(ctx, backend, "vault.kdbx", verifier)
	if err != nil {
		t.Fatalf("ReadPulled: %v", err)
	}
	if backend.calls != 1 || backend.gotNam != "vault.kdbx" || backend.gotCtx != ctx {
		t.Fatalf("backend call = (%d, %q, %v), want (1, vault.kdbx, caller ctx)", backend.calls, backend.gotNam, backend.gotCtx)
	}
	if !bytes.Equal(pulled.Bytes(), data) {
		t.Fatalf("Pulled.Bytes() = %x, want %x", pulled.Bytes(), data)
	}
	if pulled.Revision() != revision {
		t.Fatalf("Pulled.Revision() = %q, want %q", pulled.Revision(), revision)
	}
	if !bytes.Equal(verifiedBytes, data) || verifiedRevision != revision {
		t.Fatalf("verifier saw (%x, %q), want (%x, %q)", verifiedBytes, verifiedRevision, data, revision)
	}
}

func TestReadPulledMutationIsolation(t *testing.T) {
	original := []byte("original-ciphertext")
	backend := &readOnlyFakeBackend{result: mustResult(t, original, "rev-1")}

	var pullInput []byte
	verifier := func(_ context.Context, got []byte, _ vaultfilebackend.Revision) error {
		pullInput = got
		// Try to corrupt what it was given.
		for i := range got {
			got[i] = 'X'
		}
		return nil
	}

	pulled, err := ReadPulled(context.Background(), backend, "v.kdbx", verifier)
	if err != nil {
		t.Fatalf("ReadPulled: %v", err)
	}

	// Verifier mutation must not reach Pulled or the backend result.
	if !bytes.Equal(pulled.Bytes(), original) {
		t.Fatalf("Pulled.Bytes() = %q, want %q after verifier mutation", pulled.Bytes(), original)
	}
	if !bytes.Equal(backend.result.Bytes, original) {
		t.Fatalf("backend result bytes mutated to %q, want %q", backend.result.Bytes, original)
	}

	// Verifier mutation must not reach a later accessor result either.
	for i := range pullInput {
		pullInput[i] = 'Y'
	}
	if !bytes.Equal(pulled.Bytes(), original) {
		t.Fatalf("Pulled.Bytes() = %q after kept verifier slice mutated, want %q", pulled.Bytes(), original)
	}

	// Caller mutation of the returned copy must not reach Pulled.
	out := pulled.Bytes()
	for i := range out {
		out[i] = 'Z'
	}
	if !bytes.Equal(pulled.Bytes(), original) {
		t.Fatalf("Pulled.Bytes() = %q after accessor result mutated, want %q", pulled.Bytes(), original)
	}

	// The accessors return independent copies each time.
	if a, b := pulled.Bytes(), pulled.Bytes(); &a[0] == &b[0] {
		t.Fatal("Pulled.Bytes() returned a shared backing array")
	}
}

func TestReadPulledRejectsInvalidBackendResult(t *testing.T) {
	tests := []struct {
		name   string
		result vaultfilebackend.ReadResult
	}{
		{name: "nil bytes", result: mustResult(t, nil, "rev")},
		{name: "empty bytes", result: mustResult(t, []byte{}, "rev")},
		{name: "oversize bytes", result: mustResult(t, make([]byte, MaxPulledBytes+1), "rev")},
		{name: "zero revision", result: mustResult(t, []byte("x"), "")},
		{name: "oversize revision", result: mustResult(t, []byte("x"), strings.Repeat("r", MaxPulledRevisionSize+1))},
		{name: "both invalid", result: mustResult(t, nil, "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &readOnlyFakeBackend{result: tt.result}
			verifierCalls := 0
			verifier := func(context.Context, []byte, vaultfilebackend.Revision) error {
				verifierCalls++
				return nil
			}

			_, err := ReadPulled(context.Background(), backend, "v.kdbx", verifier)
			if !errors.Is(err, ErrBackendResult) {
				t.Fatalf("err = %v, want ErrBackendResult", err)
			}
			if verifierCalls != 0 {
				t.Fatalf("verifier called %d times on invalid result, want 0", verifierCalls)
			}
		})
	}
}

func TestReadPulledAcceptsBoundarySizes(t *testing.T) {
	result := mustResult(t, make([]byte, MaxPulledBytes), strings.Repeat("r", MaxPulledRevisionSize))
	backend := &readOnlyFakeBackend{result: result}
	verifier := func(context.Context, []byte, vaultfilebackend.Revision) error { return nil }

	pulled, err := ReadPulled(context.Background(), backend, "v.kdbx", verifier)
	if err != nil {
		t.Fatalf("ReadPulled at limits: %v", err)
	}
	if len(pulled.Bytes()) != MaxPulledBytes || len(pulled.Revision()) != MaxPulledRevisionSize {
		t.Fatalf("Pulled sizes = (%d, %d), want (%d, %d)", len(pulled.Bytes()), len(pulled.Revision()), MaxPulledBytes, MaxPulledRevisionSize)
	}
}

func TestReadPulledPropagatesBackendError(t *testing.T) {
	backend := &readOnlyFakeBackend{err: vaultfilebackend.ErrNotFound}
	verifierCalls := 0
	verifier := func(context.Context, []byte, vaultfilebackend.Revision) error {
		verifierCalls++
		return nil
	}

	_, err := ReadPulled(context.Background(), backend, "missing.kdbx", verifier)
	if !errors.Is(err, vaultfilebackend.ErrNotFound) {
		t.Fatalf("err = %v, want to wrap ErrNotFound", err)
	}
	if errors.Is(err, ErrBackendResult) || errors.Is(err, ErrVerification) || errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("backend error misclassified: %v", err)
	}
	if verifierCalls != 0 {
		t.Fatalf("verifier called %d times after backend error, want 0", verifierCalls)
	}
}

func TestReadPulledPropagatesVerifierError(t *testing.T) {
	backend := &readOnlyFakeBackend{result: mustResult(t, []byte("ciphertext"), "rev-2")}
	verifier := func(_ context.Context, data []byte, rev vaultfilebackend.Revision) error {
		if !bytes.Equal(data, []byte("ciphertext")) || rev != "rev-2" {
			t.Fatalf("verifier saw (%q, %q), want exact backend result", data, rev)
		}
		return context.Canceled
	}

	_, err := ReadPulled(context.Background(), backend, "v.kdbx", verifier)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("err = %v, want ErrVerification", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want to wrap the verifier error", err)
	}
	if errors.Is(err, ErrBackendResult) {
		t.Fatalf("verifier rejection misclassified as backend result: %v", err)
	}
}

func TestReadPulledGenericVerifierError(t *testing.T) {
	backend := &readOnlyFakeBackend{result: mustResult(t, []byte("ciphertext"), "rev-3")}
	verifier := func(context.Context, []byte, vaultfilebackend.Revision) error { return errVerifyRejected }

	_, err := ReadPulled(context.Background(), backend, "v.kdbx", verifier)
	if !errors.Is(err, ErrVerification) || !errors.Is(err, errVerifyRejected) {
		t.Fatalf("err = %v, want ErrVerification wrapping errVerifyRejected", err)
	}
}

func TestReadPulledWithMemoryBackend(t *testing.T) {
	ctx := context.Background()
	mem := vaultfilebackend.NewMemory()
	want := []byte("encrypted-vault-file")
	if err := mem.CreateIfAbsent(ctx, "vault.kdbx", want); err != nil {
		t.Fatalf("CreateIfAbsent: %v", err)
	}
	stored, err := mem.Read(ctx, "vault.kdbx")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	pulled, err := ReadPulled(ctx, mem, "vault.kdbx", func(_ context.Context, data []byte, rev vaultfilebackend.Revision) error {
		// The caller checks the result against its pinned anchor: both the
		// bytes and the revision must match what it already trusts.
		if rev != stored.Revision {
			return errVerifyRejected
		}
		if !bytes.Equal(data, want) {
			return errVerifyRejected
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ReadPulled: %v", err)
	}
	if !bytes.Equal(pulled.Bytes(), want) || pulled.Revision() != stored.Revision {
		t.Fatalf("Pulled = (%q, %q), want (%q, %q)", pulled.Bytes(), pulled.Revision(), want, stored.Revision)
	}

	// A pinned anchor that does not match must reject the pull.
	_, err = ReadPulled(ctx, mem, "vault.kdbx", func(context.Context, []byte, vaultfilebackend.Revision) error {
		return errVerifyRejected
	})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("mismatched anchor: err = %v, want ErrVerification", err)
	}
}
