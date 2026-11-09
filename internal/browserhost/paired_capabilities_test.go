package browserhost

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
)

// attachmentWireCapability is the literal capability the extension checks
// before it enables attachment upload (browser-extension/core.js
// ATTACHMENT_CAPABILITY). It is part of the fixed SupportedCapabilities
// baseline, so every authority-granting response must carry it.
const attachmentWireCapability = "attachments-v1"

func pairedCapabilitiesSession(t *testing.T) *personal.Session {
	t.Helper()
	path := filepath.Join(t.TempDir(), "paired-capabilities.ll")
	key := bytes.Repeat([]byte{9}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	if _, e := s.AddLogin("Paired", "paired-user", "paired-secret"); e != nil {
		t.Fatal(e)
	}
	return s
}

func pairedCapabilitiesClipboardManager() *nativeclipboard.Manager {
	fake := &clipboardFake{}
	return nativeclipboard.NewManagerWithWriter(fake.dispatch, fake.write, fake.clear)
}

func hasCapability(capabilities []string, want string) bool {
	for _, capability := range capabilities {
		if capability == want {
			return true
		}
	}
	return false
}

// assertBaselineCapabilities requires the complete fixed negotiation list,
// including the attachment capability, and no clipboard lease unless the host
// owns a native clipboard manager.
func assertBaselineCapabilities(t *testing.T, label string, capabilities []string, clipboard bool) {
	t.Helper()
	wantLen := len(SupportedCapabilities())
	if clipboard {
		wantLen++
	}
	if len(capabilities) != wantLen {
		t.Fatalf("%s: capabilities %v, want %d entries (baseline %v, clipboard=%v)", label, capabilities, wantLen, SupportedCapabilities(), clipboard)
	}
	for _, capability := range SupportedCapabilities() {
		if !hasCapability(capabilities, capability) {
			t.Fatalf("%s: missing baseline capability %q in %v", label, capability, capabilities)
		}
	}
	if !hasCapability(capabilities, attachmentWireCapability) {
		t.Fatalf("%s: missing attachment capability %q in %v", label, attachmentWireCapability, capabilities)
	}
	if got := hasCapability(capabilities, clipboardCapability); got != clipboard {
		t.Fatalf("%s: clipboard capability advertised=%v, want %v (%v)", label, got, clipboard, capabilities)
	}
}

// TestStandaloneApprovePairAdvertisesBaselineCapabilities pins the regression:
// manual standalone pairing used to answer with the fixed baseline list, then a
// shared-only capabilities() gate silently turned the answer into nil and the
// live popup disabled attachment upload (zero file count).
func TestStandaloneApprovePairAdvertisesBaselineCapabilities(t *testing.T) {
	s := pairedCapabilitiesSession(t)
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	t.Cleanup(c.Close)
	if e := c.Handle(Request{V: 1, ID: reqID(101), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if e := c.ApprovePair(s); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	if len(all) != 1 {
		t.Fatalf("standalone pairing wrote %d responses", len(all))
	}
	paired := all[0]
	if paired.Type != "paired" || paired.Capability == "" {
		t.Fatalf("standalone pairing: %#v", paired)
	}
	if paired.DesktopConnected {
		t.Fatal("standalone pairing falsely reported desktop_connected")
	}
	assertBaselineCapabilities(t, "standalone paired", paired.Capabilities, false)
}

// TestStandaloneApproveQuickPairAdvertisesBaselineCapabilities covers the
// native popup pairing gesture, which takes the same response path.
func TestStandaloneApproveQuickPairAdvertisesBaselineCapabilities(t *testing.T) {
	s := pairedCapabilitiesSession(t)
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	t.Cleanup(c.Close)
	if e := c.Handle(Request{V: 1, ID: reqID(102), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if e := c.ApproveQuickPair(s); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	if len(all) != 1 || all[0].Type != "paired" || !all[0].QuickFill {
		t.Fatalf("quick pairing: %#v", all)
	}
	if all[0].DesktopConnected {
		t.Fatal("standalone quick pairing falsely reported desktop_connected")
	}
	assertBaselineCapabilities(t, "standalone quick paired", all[0].Capabilities, false)
}

// TestStandaloneUnlockedPushAdvertisesBaselineCapabilities checks the real
// "unlocked" grant pushed to an already connected standalone client.
func TestStandaloneUnlockedPushAdvertisesBaselineCapabilities(t *testing.T) {
	s := pairedCapabilitiesSession(t)
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	t.Cleanup(c.Close)
	if e := c.Handle(Request{V: 1, ID: reqID(103), Type: "status"}); e != nil {
		t.Fatal(e)
	}
	if e := c.bindDesktopSession(s, 7, false, true); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	unlocked := all[len(all)-1]
	if unlocked.Type != "unlocked" || unlocked.Capability == "" || !unlocked.Unlocked {
		t.Fatalf("standalone unlocked push: %#v", unlocked)
	}
	assertBaselineCapabilities(t, "standalone unlocked", unlocked.Capabilities, false)
}

// TestSharedApprovePairAdvertisesClipboardOnlyWithManager keeps the clipboard
// lease additive: a shared host with a native manager advertises it where the
// platform supports an owner-safe lease, while a shared host without a manager
// stays on the plain baseline. Darwin deliberately reports no native lease
// support, because its pasteboard API cannot revoke only this process's owner.
func TestSharedApprovePairAdvertisesClipboardOnlyWithManager(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		manager   bool
		clipboard bool
	}{
		{name: "with manager", manager: true, clipboard: true},
		{name: "without manager", manager: false, clipboard: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			wantClipboard := testCase.clipboard && nativeclipboard.NativeLeaseSupported()
			s := pairedCapabilitiesSession(t)
			out := &memoryPipe{}
			c := NewDesktopConnection(NewWriter(out, time.Second), nil)
			t.Cleanup(c.Close)
			if testCase.manager {
				c.SetBroker(NewBroker(BrokerCallbacks{NewClipboard: func() (*nativeclipboard.Manager, time.Duration) {
					return pairedCapabilitiesClipboardManager(), 3 * time.Second
				}}))
			}
			if e := c.Handle(Request{V: 1, ID: reqID(104), Type: "hello"}); e != nil {
				t.Fatal(e)
			}
			if e := c.ApprovePair(s); e != nil {
				t.Fatal(e)
			}
			all := out.responses(t)
			paired := all[len(all)-1]
			if paired.Type != "paired" || paired.Capability == "" {
				t.Fatalf("shared pairing: %#v", paired)
			}
			assertBaselineCapabilities(t, "shared paired", paired.Capabilities, wantClipboard)
		})
	}
}

// TestSharedUnlockedPushIncludesClipboardWithManager also pins the desktop
// "unlocked" push, which shares the paired-capability policy.
func TestSharedUnlockedPushIncludesClipboardWithManager(t *testing.T) {
	s := pairedCapabilitiesSession(t)
	out := &memoryPipe{}
	c := NewDesktopConnection(NewWriter(out, time.Second), nil)
	t.Cleanup(c.Close)
	c.SetBroker(NewBroker(BrokerCallbacks{NewClipboard: func() (*nativeclipboard.Manager, time.Duration) {
		return pairedCapabilitiesClipboardManager(), 3 * time.Second
	}}))
	if e := c.bindDesktopSession(s, 3, true, true); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	unlocked := all[len(all)-1]
	if unlocked.Type != "unlocked" || !unlocked.DesktopConnected {
		t.Fatalf("shared unlocked push: %#v", unlocked)
	}
	assertBaselineCapabilities(t, "shared unlocked", unlocked.Capabilities, nativeclipboard.NativeLeaseSupported())
}

// TestStandaloneStatusCapabilitiesRemainEmpty keeps the historical status
// policy intact: standalone status/prepair answers still advertise no
// capability list, and a locked shared host advertises neither clipboard nor
// any authority until the vault is unlocked.
func TestStandaloneStatusCapabilitiesRemainEmpty(t *testing.T) {
	t.Run("standalone status", func(t *testing.T) {
		out := &memoryPipe{}
		c := NewConnection(NewWriter(out, time.Second), nil)
		t.Cleanup(c.Close)
		if e := c.Handle(Request{V: 1, ID: reqID(105), Type: "status"}); e != nil {
			t.Fatal(e)
		}
		all := out.responses(t)
		status := all[len(all)-1]
		if status.Type != "status" || status.DesktopConnected || status.Unlocked || status.Paired {
			t.Fatalf("standalone prepair status: %#v", status)
		}
		if status.Capabilities != nil {
			t.Fatalf("standalone status advertised capabilities: %v", status.Capabilities)
		}
		if caps := c.capabilities(); caps != nil {
			t.Fatalf("standalone capabilities() returned %v", caps)
		}
	})

	t.Run("standalone hello keeps pairing unanswered", func(t *testing.T) {
		out := &memoryPipe{}
		c := NewConnection(NewWriter(out, time.Second), nil)
		t.Cleanup(c.Close)
		if e := c.Handle(Request{V: 1, ID: reqID(106), Type: "hello"}); e != nil {
			t.Fatal(e)
		}
		if all := out.responses(t); len(all) != 0 {
			t.Fatalf("prepair hello answered: %#v", all)
		}
	})

	t.Run("shared locked status", func(t *testing.T) {
		out := &memoryPipe{}
		c := NewDesktopConnection(NewWriter(out, time.Second), nil)
		t.Cleanup(c.Close)
		c.SetBroker(NewBroker(BrokerCallbacks{NewClipboard: func() (*nativeclipboard.Manager, time.Duration) {
			return pairedCapabilitiesClipboardManager(), 3 * time.Second
		}}))
		if e := c.Handle(Request{V: 1, ID: reqID(107), Type: "status"}); e != nil {
			t.Fatal(e)
		}
		all := out.responses(t)
		status := all[len(all)-1]
		if status.Type != "status" || !status.DesktopConnected || status.Unlocked || !status.VaultLocked || status.Paired {
			t.Fatalf("shared locked status: %#v", status)
		}
		// The locked shared status keeps the historical shared-only helper: it
		// still lists the negotiated baseline (plus the clipboard lease this host
		// really owns), but never grants a capability or authority token.
		if status.Capability != "" {
			t.Fatalf("locked status granted a capability: %#v", status)
		}
		if status.Capabilities == nil {
			t.Fatal("shared status lost its negotiated baseline")
		}
		if got, want := status.Capabilities, c.capabilities(); len(got) != len(want) {
			t.Fatalf("shared status drifted from capabilities(): %v vs %v", got, want)
		}
	})
}
