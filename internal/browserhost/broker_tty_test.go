//go:build linux || darwin

package browserhost

import (
	"errors"
	"os"
	"testing"
)

// withTTYSeams swaps the broker's kernel lookup and, when handle is not nil,
// the client's terminal-node opener for one test and restores both when it
// ends. peerTTYAttestor is called by CurrentTTYIdentity for this process's own
// PID and by AttestCLIRunTTY for the peer's, so the fixture serves both.
func withTTYSeams(t *testing.T, terminal string, dev uint64, peerOK bool, handle func(string) (*os.File, error)) {
	withTTYSeamsPlatform(t, terminal, dev, peerOK, handle, true)
}

// withTTYSeamsPlatform is withTTYSeams with control over whether the platform
// count as able to attest, so the committed fail-closed path can run natively.
func withTTYSeamsPlatform(t *testing.T, terminal string, dev uint64, peerOK bool, handle func(string) (*os.File, error), platform bool) {
	t.Helper()
	withTTYSeamsCounted(t, terminal, dev, peerOK, handle, platform, nil)
}

// withTTYSeamsCounting is withTTYSeams with a fixture kernel lookup that
// records every call in *calls, so a test can prove the peer attestation seam
// is never reached.
func withTTYSeamsCounting(t *testing.T, terminal string, dev uint64, peerOK bool, calls *int) {
	t.Helper()
	withTTYSeamsCounted(t, terminal, dev, peerOK, nil, true, calls)
}

// withTTYSeamsCounted is withTTYSeamsPlatform plus an optional call counter
// for the fixture kernel lookup (when calls is not nil).
func withTTYSeamsCounted(t *testing.T, terminal string, dev uint64, peerOK bool, handle func(string) (*os.File, error), platform bool, calls *int) {
	t.Helper()
	oldAttest, oldOpen, oldPlatform := peerTTYAttestor, currentTTYNodeOpener, attestationPlatformDisabled
	peerTTYAttestor = func(pid int) (string, uint64, uint32, bool) {
		if calls != nil {
			*calls++
		}
		if !peerOK || pid <= 0 {
			return "", 0, 0, false
		}
		unit, ok := devUnit(dev)
		if !ok {
			return "", 0, 0, false
		}
		return terminal, dev, unit, true
	}
	if handle != nil {
		currentTTYNodeOpener = handle
	}
	attestationPlatformDisabled = !platform
	t.Cleanup(func() {
		peerTTYAttestor, currentTTYNodeOpener, attestationPlatformDisabled = oldAttest, oldOpen, oldPlatform
	})
}

// fixedOpener always returns the given file (or error), whatever path it is
// asked for, so a test can hand the checkpoint a mismatched handle.
func fixedOpener(f *os.File, err error) func(string) (*os.File, error) {
	return func(string) (*os.File, error) { return f, err }
}

// trustableTTYNode returns the node path and device of the controlling
// terminal of this test process, or skips when it has none that this build
// can attest. A skip here is legitimate only when the test binary truly has
// no controlling terminal; skipOrFailWithoutTTY enforces that.
func trustableTTYNode(t *testing.T) (string, uint64) {
	t.Helper()
	path, _, _, ok := peerControllingTerminal(os.Getpid())
	if !ok {
		skipOrFailWithoutTTY(t, "kernel lookup cannot attest this process's controlling terminal")
	}
	_, dev, _, ok := ttyNodeIdentity(path)
	if !ok {
		skipOrFailWithoutTTY(t, "controlling terminal node is not stat'able under the local policy")
	}
	return path, dev
}

// skipOrFailWithoutTTY records that a terminal-dependent test could not run
// because the process has no controlling terminal. Under the PTY smoke
// fixture a controlling terminal is required, so the same condition fails the
// test instead of skipping it.
func skipOrFailWithoutTTY(t *testing.T, reason string) {
	t.Helper()
	if smoke := os.Getenv("BROWSERHOST_TTY_SMOKE"); smoke != "" {
		t.Fatalf("PTY smoke requires a controlling terminal: %s", reason)
	}
	t.Skipf("no controlling terminal: %s", reason)
}

// TestCurrentTTYIdentityUsesKernelAttestedNode proves the client identity
// comes from the kernel's controlling terminal plus an opened node of exactly
// that terminal, and that every other shape is unavailable.
func TestCurrentTTYIdentityUsesKernelAttestedNode(t *testing.T) {
	node, nodeDev := trustableTTYNode(t)

	// The real open of the kernel node yields the kernel identity.
	withTTYSeams(t, node, nodeDev, true, openTTYNode)
	name, peerID, e := CurrentTTYIdentity()
	unit, _ := devUnit(nodeDev)
	if e != nil || name != node || peerID != encodeTTYPeerID(unit) || len(peerID) != 8 {
		t.Fatalf("identity: %q %q %v (kernel node %q)", name, peerID, e, node)
	}
	if got, ok := parseTTYPeerID(peerID); !ok || got != unit {
		t.Fatalf("peer id round trip: %q -> %d %v, want %d", peerID, got, ok, unit)
	}

	// The opener receives the kernel-derived path, never a caller's string.
	var opened []string
	record := func(p string) (*os.File, error) {
		opened = append(opened, p)
		return openTTYNode(p)
	}
	withTTYSeams(t, node, nodeDev, true, record)
	if _, _, e := CurrentTTYIdentity(); e != nil || len(opened) != 1 || opened[0] != node {
		t.Fatalf("opener paths %v (%v), want exactly %q", opened, e, node)
	}

	// /dev/tty is a cloning-device alias, never opened as an identity.
	withTTYSeams(t, "/dev/tty", nodeDev, true, fixedOpener(nil, errCLIRunUnavailable))
	if _, _, e := CurrentTTYIdentity(); !errors.Is(e, errCLIRunUnavailable) {
		t.Fatalf("/dev/tty as kernel path: %v", e)
	}
}

// TestCurrentTTYIdentityRejectsMismatchedHandle proves that a handle that is
// not a terminal, or not exactly the kernel-attested device, is unavailable.
func TestCurrentTTYIdentityRejectsMismatchedHandle(t *testing.T) {
	node, nodeDev := trustableTTYNode(t)

	// A regular file is not a terminal, even though it fstats successfully.
	regular, e := os.CreateTemp(t.TempDir(), "not-a-tty")
	if e != nil {
		t.Fatal(e)
	}
	defer regular.Close()
	withTTYSeams(t, node, nodeDev, true, fixedOpener(regular, nil))
	if _, _, e := CurrentTTYIdentity(); !errors.Is(e, errCLIRunUnavailable) {
		t.Fatalf("regular file: %v", e)
	}

	// A handle for another real terminal, while the kernel names ours, is a
	// device mismatch.
	otherPath, _, realOther := brokerTTYOtherNode(nodeDev)
	t.Logf("other real pty node: %s (real=%v)", otherPath, realOther)
	if realOther {
		otherFile, e := openTTYNode(otherPath)
		if e != nil {
			t.Fatalf("open %s: %v", otherPath, e)
		}
		defer otherFile.Close()
		withTTYSeams(t, node, nodeDev, true, fixedOpener(otherFile, nil))
		if name, _, e := CurrentTTYIdentity(); !errors.Is(e, errCLIRunUnavailable) {
			t.Fatalf("handle for %s accepted for %s: %q %v", otherPath, node, name, e)
		}
	}

	// An opener failure, or a nil handle, is unavailable.
	withTTYSeams(t, node, nodeDev, true, fixedOpener(nil, errors.New("fixture open failure")))
	if _, _, e := CurrentTTYIdentity(); !errors.Is(e, errCLIRunUnavailable) {
		t.Fatalf("opener failure: %v", e)
	}
	withTTYSeams(t, node, nodeDev, true, fixedOpener(nil, nil))
	if _, _, e := CurrentTTYIdentity(); !errors.Is(e, errCLIRunUnavailable) {
		t.Fatalf("nil handle: %v", e)
	}

	// No controlling terminal, or an unnameable device, is unavailable.
	withTTYSeams(t, "", 0, false, openTTYNode)
	if _, _, e := CurrentTTYIdentity(); !errors.Is(e, errCLIRunUnavailable) {
		t.Fatalf("no terminal: %v", e)
	}
	withTTYSeams(t, "/dev/locklark-fixture-tty", brokerTTYForeignDev(), true, openTTYNode)
	if _, _, e := CurrentTTYIdentity(); !errors.Is(e, errCLIRunUnavailable) {
		t.Fatalf("unnameable device: %v", e)
	}
}

// TestCurrentTTYIdentityRejectsChangedAttestation proves the checkpoint
// re-attests after the handle check: a controlling terminal that changes path
// or device between the two kernel reads yields no identity.
func TestCurrentTTYIdentityRejectsChangedAttestation(t *testing.T) {
	node, nodeDev := trustableTTYNode(t)
	for name, second := range map[string][2]any{
		"path changed":   {node + "x", nodeDev},
		"device changed": {node, otherTTYDev(nodeDev)},
	} {
		calls := 0
		oldAttest, oldOpen := peerTTYAttestor, currentTTYNodeOpener
		peerTTYAttestor = func(pid int) (string, uint64, uint32, bool) {
			calls++
			if calls == 1 {
				unit, _ := devUnit(nodeDev)
				return node, nodeDev, unit, true
			}
			dev := second[1].(uint64)
			unit, ok := devUnit(dev)
			if !ok {
				return "", 0, 0, false
			}
			return second[0].(string), dev, unit, true
		}
		currentTTYNodeOpener = openTTYNode
		_, _, e := CurrentTTYIdentity()
		peerTTYAttestor, currentTTYNodeOpener = oldAttest, oldOpen
		if !errors.Is(e, errCLIRunUnavailable) {
			t.Fatalf("%s: %v", name, e)
		}
		if calls != 2 {
			t.Fatalf("%s: %d attests, want 2", name, calls)
		}
	}
	// Two identical attestations are accepted, so the rejections above are
	// caused by the change and not by any steady-state defect.
	calls := 0
	var wantPeerID string
	withTTYSeams(t, node, nodeDev, true, func(p string) (*os.File, error) {
		calls++
		return openTTYNode(p)
	})
	unit, _ := devUnit(nodeDev)
	wantPeerID = encodeTTYPeerID(unit)
	name, peerID, e := CurrentTTYIdentity()
	if e != nil || name != node || peerID != wantPeerID || calls != 1 {
		t.Fatalf("steady identity %q %q %v (opens %d)", name, peerID, e, calls)
	}
}

// TestVerifyCLIRunTTYMatchesAuthenticatedPeer proves the broker compares the
// declared name's device with the authenticated peer's kernel controlling
// terminal, and refuses every declared value that only looks right.
func TestVerifyCLIRunTTYMatchesAuthenticatedPeer(t *testing.T) {
	peer := Peer{User: "UID 501", PID: 991, Process: "/fixture/bin/locklark"}
	if !peerTTYAttestationAvailable {
		// A platform without a peer-CTTY proof (Linux, Android on the Linux
		// build, and unsupported platforms) has no kernel-backed association
		// proving that a peer's CTTY is this broker's terminal object, so the
		// broker fails closed before any lookup: both entry points are
		// explicitly unavailable (not a refusal) and the peer attestation seam
		// is never called. No PTY is needed.
		t.Run("peer attestation unavailable", func(t *testing.T) {
			calls := 0
			withTTYSeamsCounting(t, "/dev/pts/7", brokerTTYForeignDev(), true, &calls)
			if attested, e := AttestCLIRunTTY(peer); !errors.Is(e, errCLIRunUnavailable) || errors.Is(e, errCLIRunInvalid) || attested != (CLIRunTTYAttestation{}) {
				t.Fatalf("attest: %#v %v", attested, e)
			}
			if e := verifyCLIRunTTY(peer, "/dev/pts/7", CLIRunTTYPlatform(), ""); !errors.Is(e, errCLIRunUnavailable) || errors.Is(e, errCLIRunInvalid) {
				t.Fatalf("verify: %v", e)
			}
			if calls != 0 {
				t.Fatalf("peer attestation seam called %d times without a peer proof, want 0", calls)
			}
		})
		return
	}
	node, dev := trustableTTYNode(t)
	withTTYSeams(t, node, dev, true, nil)
	platform := CLIRunTTYPlatform()
	if e := verifyCLIRunTTY(peer, node, platform, ""); e != nil {
		t.Fatalf("matching peer terminal refused: %v", e)
	}
	attested, e := AttestCLIRunTTY(peer)
	if e != nil || attested.Dev != dev || attested.Name != node {
		t.Fatalf("attestation: %#v %v", attested, e)
	}
	// A declared device number is never authority.
	if e := verifyCLIRunTTY(peer, node, platform, encodeTTYPeerID(attested.Unit)); !errors.Is(e, errCLIRunInvalid) {
		t.Fatalf("declared peer id: %v", e)
	}
	// A platform label from somewhere else is a mismatch.
	if e := verifyCLIRunTTY(peer, node, "other-os", ""); !errors.Is(e, errCLIRunInvalid) {
		t.Fatalf("foreign platform: %v", e)
	}
	// A name that does not project to a trusted node is refused.
	if e := verifyCLIRunTTY(peer, "/fixture/fake-tty", platform, ""); !errors.Is(e, errCLIRunInvalid) {
		t.Fatalf("untrusted declared name: %v", e)
	}
	if e := verifyCLIRunTTY(peer, node+"/", platform, ""); !errors.Is(e, errCLIRunInvalid) {
		t.Fatalf("dirty declared name: %v", e)
	}
	if e := verifyCLIRunTTY(peer, "", platform, ""); !errors.Is(e, errCLIRunInvalid) {
		t.Fatalf("empty declared name: %v", e)
	}
}

// TestVerifyCLIRunTTYUnavailableWithoutKernelIdentity proves a peer without a
// kernel controlling terminal, or a kernel value the node does not confirm, is
// explicitly unavailable (not a refusal) before approval.
func TestVerifyCLIRunTTYUnavailableWithoutKernelIdentity(t *testing.T) {
	peer := Peer{User: "UID 501", PID: 992, Process: "/fixture/bin/locklark"}
	node, dev := trustableTTYNode(t)
	for name, setup := range map[string]func(){
		"no kernel terminal": func() { withTTYSeams(t, "", 0, false, nil) },
		"node path invalid":  func() { withTTYSeams(t, "relative/ttys", dev, true, nil) },
	} {
		setup()
		if e := verifyCLIRunTTY(peer, node, CLIRunTTYPlatform(), ""); !errors.Is(e, errCLIRunUnavailable) || errors.Is(e, errCLIRunInvalid) {
			t.Fatalf("%s: verify: %v", name, e)
		}
		if _, e := AttestCLIRunTTY(peer); !errors.Is(e, errCLIRunUnavailable) {
			t.Fatalf("%s: attest: %v", name, e)
		}
	}
	// A syntactically valid but nonexistent node is unavailable too; the
	// kernel lookup (and so attestation) accepts nothing for a missing node.
	withTTYSeams(t, "/dev/locklark-untrusted-tty-node", dev, true, nil)
	if e := verifyCLIRunTTY(peer, "/dev/locklark-untrusted-tty-node", CLIRunTTYPlatform(), ""); !errors.Is(e, errCLIRunUnavailable) || errors.Is(e, errCLIRunInvalid) {
		t.Fatalf("missing node: verify: %v", e)
	}
	withTTYSeams(t, node, dev, true, nil)
	if _, e := AttestCLIRunTTY(Peer{}); !errors.Is(e, errCLIRunUnavailable) {
		t.Fatalf("zero pid: %v", e)
	}
	if e := verifyCLIRunTTY(Peer{}, node, CLIRunTTYPlatform(), ""); !errors.Is(e, errCLIRunUnavailable) {
		t.Fatalf("zero pid verify: %v", e)
	}
}

// TestTTYUnsupportedPlatformFailsClosed proves that without a platform
// attestation every checkpoint reports unavailable and nothing is opened, so a
// declared string can never stand in for a kernel identity.
func TestTTYUnsupportedPlatformFailsClosed(t *testing.T) {
	peer := Peer{User: "UID 501", PID: 993, Process: "/fixture/bin/locklark"}
	opened := 0
	withTTYSeamsPlatform(t, "/dev/locklark-fixture-tty", brokerTTYForeignDev(), true, func(string) (*os.File, error) {
		opened++
		return nil, errCLIRunUnavailable
	}, false)
	if _, _, e := CurrentTTYIdentity(); !errors.Is(e, errCLIRunUnavailable) {
		t.Fatalf("identity: %v", e)
	}
	if _, e := AttestCLIRunTTY(peer); !errors.Is(e, errCLIRunUnavailable) {
		t.Fatalf("attest: %v", e)
	}
	if e := verifyCLIRunTTY(peer, "/dev/locklark-fixture-tty", CLIRunTTYPlatform(), ""); !errors.Is(e, errCLIRunUnavailable) || errors.Is(e, errCLIRunInvalid) {
		t.Fatalf("verify: %v", e)
	}
	if opened != 0 {
		t.Fatalf("opener called %d times on an unsupported platform", opened)
	}
}
