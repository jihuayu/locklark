package personal

import (
	"context"
	"errors"
	"os"

	"github.com/jihuayu/locklark/internal/cliprofile"
)

// runBundleProviderMaxValueBytes is the strict per-slot ceiling for values a
// desktop provider may return. It is the same 64 KiB bound used by the cli-run
// v2 wire so a value that crossed the broker boundary can never be rendered by
// a slightly more permissive local profile.
const runBundleProviderMaxValueBytes = 64 << 10

// ErrRunBundleProviderOpaque reports an attempt to format or serialize the
// opaque provider carrier. Neither operation is ever allowed to expose a
// credential byte.
var ErrRunBundleProviderOpaque = errors.New("run bundle provider result is opaque and cannot be serialized")

// RunBundleProviderResult is the owned result of one external preparation. The
// adapter takes ownership of Values and zeroes every byte after rendering,
// execution, cancellation or any error. The receipt is the canonical
// non-secret authorization binding; it never claims that a process ran.
//
// The carrier deliberately stringifies and marshals to a redacted refusal so a
// log statement, error wrapper or accidental JSON encoding can never disclose
// the values map.
type RunBundleProviderResult struct {
	Values  map[string][]byte
	Receipt RunBundleGrantReceipt
}

// String and GoString redact the carrier for %v, %+v, %s and %#v.
func (RunBundleProviderResult) String() string   { return "[run bundle provider result]" }
func (RunBundleProviderResult) GoString() string { return "[run bundle provider result]" }

// MarshalJSON refuses instead of serializing the values map.
func (RunBundleProviderResult) MarshalJSON() ([]byte, error) {
	return nil, ErrRunBundleProviderOpaque
}

// RunBundleProvider prepares the exact requested slots for one run bundle.
// request and targets are private clones; the provider may mutate them without
// changing the signed intent or the set the adapter validates. root is the
// actual 0700 temporary run root that was already created for this run and must
// not be created, moved or retained by the provider. Returned values are owned
// by the adapter, who zeroes them after use.
type RunBundleProvider func(ctx context.Context, request RunBundleRequest, targets []BundleTarget, root string) (RunBundleProviderResult, error)

// RunBundleWithProvider runs the same private-temp, render, materialize and
// direct-exec implementation as RunBundle, but obtains the slot values from an
// external provider instead of opening the local vault. The provider sees the
// already-created run root so a desktop broker can bind its approval to the
// exact filesystem scope. Every value is still rendered into the same isolated
// root and every child stream is inherited without capture.
//
// A provider error is returned unchanged only after the temporary root has been
// removed and every returned value zeroed, so a caller can safely classify a
// known pre-connect "unavailable" outcome before considering any other path.
func RunBundleWithProvider(ctx context.Context, targets []BundleTarget, request RunBundleRequest, provider RunBundleProvider) (RunReceipt, error) {
	return runBundleWithProvider(ctx, targets, request, provider, createRunCLITemp, func(ctx context.Context, req RunBundleRequest, root string, rendered cliprofile.RenderedBundle) (int, error) {
		return executeRunBundle(ctx, req, root, rendered, runCLIStreams{os.Stdin, os.Stdout, os.Stderr})
	}, os.RemoveAll)
}

// runBundleWithProvider exposes the exact runBundle dependencies to package
// tests while production callers use RunBundleWithProvider. It does not add a
// second execution path: everything after preparation is the shared runBundle
// implementation.
func runBundleWithProvider(ctx context.Context, targets []BundleTarget, request RunBundleRequest, provider RunBundleProvider, createTemp func() (string, error), execute func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error), remove func(string) error) (RunReceipt, error) {
	if provider == nil {
		return RunReceipt{}, ErrRunTarget
	}
	return runBundle(ctx, targets, request, createTemp, func(s *runBundleStoreRequest) (result, error) {
		return runBundleProviderPrepare(ctx, s, provider)
	}, execute, remove)
}

// runBundleProviderPrepare adapts the external carrier into the internal result
// shape used by runBundle. Validation happens before any value reaches Render:
// the slot set must match exactly, every value must fit the per-value bound and
// the receipt must be canonical. Any refusal zeroes every returned byte.
func runBundleProviderPrepare(ctx context.Context, s *runBundleStoreRequest, provider RunBundleProvider) (result, error) {
	if ctx == nil || ctx.Err() != nil {
		return result{}, ErrRunCancelled
	}
	// The provider receives its own clones. It can never change the request or
	// target set that the adapter validates and Render later consumes.
	provided, err := provider(ctx, cloneRunBundleRequest(s.request), cloneRunBundleTargets(s.targets), s.root)
	if err != nil {
		clearBundleValues(provided.Values)
		return result{}, err
	}
	return adaptRunBundleProviderResult(provided, s.targets)
}

// adaptRunBundleProviderResult converts the external carrier into the private
// internal prepare result. The values map is retained on success and zeroed on
// every failure so no error path can leave a disclosed byte behind.
func adaptRunBundleProviderResult(provided RunBundleProviderResult, targets []BundleTarget) (result, error) {
	if len(provided.Values) != len(targets) ||
		!idOK(provided.Receipt.Session) ||
		!digestOK(provided.Receipt.Intent) ||
		!digestOK(provided.Receipt.TargetDigest) {
		clearBundleValues(provided.Values)
		return result{}, ErrRunCredential
	}
	for _, target := range targets {
		value, ok := provided.Values[target.Slot]
		if !ok || len(value) > runBundleProviderMaxValueBytes {
			clearBundleValues(provided.Values)
			return result{}, ErrRunCredential
		}
	}
	return result{
		values:            provided.Values,
		session:           provided.Receipt.Session,
		intent:            provided.Receipt.Intent,
		destinationDigest: provided.Receipt.TargetDigest,
	}, nil
}
