package personal

import "github.com/jihuayu/locklark/internal/vault"

// clearItemPasskeys zeroes every raw passkey buffer an item owns, in both
// persisted forms. Item.Passkey tracks the legacy single record and
// Item.Passkeys the versioned collection; a clear that only touched the legacy
// field would leave collection records live in memory after the authenticated
// transaction finished, so both forms are always zeroed together.
//
// Zeroing happens in place: slices copied out of an authenticated state share
// the same backing arrays, so a caller only ever observes zeroed bytes while
// the persisted KDBX payload on disk is unaffected.
func clearItemPasskeys(item *vault.Item) {
	if item == nil {
		return
	}
	for _, raw := range item.Passkeys {
		clear(raw)
	}
	clear(item.Passkey)
}
