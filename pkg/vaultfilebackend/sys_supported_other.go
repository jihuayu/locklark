//go:build !darwin && !linux

package vaultfilebackend

// dirSupported reports whether the local directory driver is implemented on
// this platform. A Windows driver (LockFileEx plus a no-replace publication)
// must pass RunConformance and the cross-process tests before it is enabled.
const dirSupported = false
