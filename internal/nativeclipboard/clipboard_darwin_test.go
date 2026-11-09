//go:build darwin && (amd64 || arm64)

package nativeclipboard

import "testing"

func TestMacPartialWriteAnchorsOriginalOwnershipCount(t *testing.T) {
	count := int64(7)
	lease, err := acquireMac(func() int64 { return count }, func() bool { count = 8; return true }, func() int64 { return count })
	if lease == nil || err != ErrWrite || lease.native.(*macLease).count != 7 {
		t.Fatal("partial write adopted a foreign count")
	}
	if result := clearMac(lease.native.(*macLease), nil, nil); result != ManualCleanup {
		t.Fatalf("partial write cleanup = %v, want ManualCleanup", result)
	}
	lease, err = acquireMac(func() int64 { return 9 }, func() bool { return false }, func() int64 { return 9 })
	if lease == nil || err != ErrWrite {
		t.Fatal("failed set lost original cleanup lease")
	}
	if result := clearMac(lease.native.(*macLease), nil, nil); result != ManualCleanup {
		t.Fatalf("failed set cleanup = %v, want ManualCleanup", result)
	}
}

// TestMacCleanupNeverDestroysForeignInterleaving models the proven TOCTOU:
// observe changeCount, a foreign process writes a new value, then the old lease
// is cleaned up. The clear closure would destroy the foreign value if invoked.
// NSPasteboard has no compare-and-clear, so Darwin cleanup must never call it.
func TestMacCleanupNeverDestroysForeignInterleaving(t *testing.T) {
	count := int64(7)
	foreign := "before-foreign-write"
	observed := count
	count++ // foreign process acquisition between observation and cleanup
	foreign = "foreign-owner-value"
	countCalled, clearCalled := false, false
	result := clearMac(
		&macLease{count: observed},
		func() int64 {
			countCalled = true
			return count
		},
		func() int64 {
			clearCalled = true
			foreign = "" // the old unconditional clearContents behavior
			return count + 1
		},
	)
	if result != ManualCleanup {
		t.Fatalf("cleanup result = %v, want terminal ManualCleanup", result)
	}
	if countCalled || clearCalled {
		t.Fatalf("Darwin cleanup invoked native probe: count=%v clear=%v", countCalled, clearCalled)
	}
	if foreign != "foreign-owner-value" {
		t.Fatalf("foreign value = %q, want it preserved", foreign)
	}
}

func TestMacNativeLeaseIsUnsupported(t *testing.T) {
	if NativeLeaseSupported() {
		t.Fatal("Darwin advertised owner-safe native cleanup without compare-and-clear")
	}
}
