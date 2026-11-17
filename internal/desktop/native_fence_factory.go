//go:build !locklark_native_acceptance

package desktop

// nativeInitialUnlockFenceForBuild is the ordinary-build factory. The tagged
// acceptance transport does not exist in this configuration, so the factory
// returns no transport immediately and performs no environment, descriptor,
// file, I/O, goroutine or wait work.
func nativeInitialUnlockFenceForBuild() *nativeFenceTransport {
	return nil
}
