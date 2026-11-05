//go:build darwin && (amd64 || arm64)

package nativeclipboard

import "testing"

func TestMacPartialWriteAnchorsOriginalOwnershipCount(t *testing.T) {
	count := int64(7)
	lease, err := acquireMac(func() int64 { return count }, func() bool { count = 8; return true }, func() int64 { return count })
	if lease == nil || err != ErrWrite || lease.native.(*macLease).count != 7 {
		t.Fatal("partial write adopted a foreign count")
	}
	cleared := false
	if clearMac(lease.native.(*macLease), func() int64 { return count }, func() int64 { cleared = true; return count + 1 }) != Superseded || cleared {
		t.Fatal("partial write cleared foreign generation")
	}
	lease, err = acquireMac(func() int64 { return 9 }, func() bool { return false }, func() int64 { return 9 })
	if lease == nil || err != ErrWrite {
		t.Fatal("failed set lost original cleanup lease")
	}
	if clearMac(lease.native.(*macLease), func() int64 { return 9 }, func() int64 { cleared = true; return 10 }) != Cleared || !cleared {
		t.Fatal("matching declared ownership was not cleaned")
	}
	if clearMac(lease.native.(*macLease), func() int64 { return 9 }, func() int64 { return 9 }) != Unavailable {
		t.Fatal("unchanged clear result was reported as cleared")
	}
}
