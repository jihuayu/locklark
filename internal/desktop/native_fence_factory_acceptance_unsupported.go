//go:build locklark_native_acceptance && !darwin && !linux

package desktop

// nativeInitialUnlockFenceForBuild on unsupported tagged platforms returns the
// existing safely unavailable transport. It reads no environment and touches
// no descriptor, so it cannot advertise a ready, adopted or normal-success
// native state.
func nativeInitialUnlockFenceForBuild() *nativeFenceTransport {
	return newNativeFenceTransport(-1, -1)
}
