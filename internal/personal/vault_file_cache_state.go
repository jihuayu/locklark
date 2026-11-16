package personal

import "time"

// VaultFileCacheState is the delivery state of already-returned UI metadata
// after an owned child was opened. The zero value is deliberately the
// non-deliverable revoked state.
//
// It is authority metadata only. It is not a fresh crypto authorization, never
// substitutes wrapper.Summary or an owned/full-factor proof, and never grants
// access to identity, material, a token, a handle or an unlock capability.
type VaultFileCacheState uint8

const (
	VaultFileCacheRevoked VaultFileCacheState = iota
	VaultFileCacheBusy
	VaultFileCacheActive
)

// VaultFileCacheState reports whether a previously returned vault-file cache
// may still be delivered. A nil or zero Session, a revoked parent, empty
// material or an expired idle deadline is revoked. If Session.mu is busy it
// returns busy unless revocation was already observable, because an
// in-progress state cannot be inferred as active. It checks only the existing
// non-blocking Session boundary and never waits for parent.mu, saveMu, child
// close or IO.
//
// The method does not call active, Unlocked or lock, does not refresh activity,
// full-unlock or idle timestamps, does not create or close children, and does
// not take saveMu. It has no input flags that could skip these checks.
func (s *Session) VaultFileCacheState() VaultFileCacheState {
	if s == nil || s.lockRequested.Load() || s.vaultFileRevoked.Load() {
		return VaultFileCacheRevoked
	}
	if !s.mu.TryLock() {
		if s.lockRequested.Load() || s.vaultFileRevoked.Load() {
			return VaultFileCacheRevoked
		}
		return VaultFileCacheBusy
	}
	defer s.mu.Unlock()
	if s.lockRequested.Load() || s.vaultFileRevoked.Load() {
		return VaultFileCacheRevoked
	}
	if len(s.material) == 0 || s.idleExpired(time.Now()) {
		return VaultFileCacheRevoked
	}
	// Confirm revocation again while still holding mu, immediately before the
	// state is released to the caller.
	if s.lockRequested.Load() || s.vaultFileRevoked.Load() {
		return VaultFileCacheRevoked
	}
	return VaultFileCacheActive
}
