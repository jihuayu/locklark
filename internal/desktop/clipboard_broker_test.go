package desktop

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
)

// TestBrowserBrokerClipboardFactoryIsPerConnectionAndSharesAppOwner proves the
// desktop IPC contract: the only clipboard capability source returns a fresh
// manager per accepted connection, and every one of them writes through the
// single App-owned native writer and global lease.
func TestBrowserBrokerClipboardFactoryIsPerConnectionAndSharesAppOwner(t *testing.T) {
	if !nativeclipboard.NativeLeaseSupported() {
		t.Skip("native clipboard leases are unavailable; platform fallback has separate coverage")
	}
	a := New()
	f := attachFakeClipboard(a)
	cb := a.browserBrokerCallbacks()
	if cb.NewClipboard == nil || cb.ClipboardClearDuration == nil {
		t.Fatal("desktop broker did not advertise the native clipboard capability")
	}
	first, ttl := cb.NewClipboard()
	second, ttl2 := cb.NewClipboard()
	if first == nil || second == nil || first == second {
		t.Fatal("each connection needs its own two-phase manager")
	}
	if ttl != 30*time.Second || ttl2 != ttl {
		t.Fatalf("factory TTL = %v/%v, want the default 30s", ttl, ttl2)
	}
	valid := func() bool { return true }
	ticket, err := first.Prepare([]byte("browser-secret"), time.Now().Add(5*time.Second), time.Time{}, valid)
	if err != nil || len(ticket) != 64 {
		t.Fatalf("prepare = %q, %v", ticket, err)
	}
	if f.value != "" {
		t.Fatal("prepare must never write the OS clipboard")
	}
	if outcome := <-first.Commit(context.Background(), ticket); outcome != nativeclipboard.Confirmed {
		t.Fatalf("commit = %v, want Confirmed", outcome)
	}
	if f.value != "browser-secret" || a.clipboardLease != f.owner {
		t.Fatal("browser write did not become the App-owned native lease")
	}
	// A zero manager clear deadline maps to the existing no-auto-clear App
	// contract; only a later explicit clear may drop this owner.
	if !a.clipboardUntil.After(time.Now().Add(365 * 24 * time.Hour)) {
		t.Fatalf("zero deadline was translated to %v", a.clipboardUntil)
	}
	ticket2, err := second.Prepare([]byte("second-secret"), time.Now().Add(5*time.Second), time.Time{}, valid)
	if err != nil {
		t.Fatalf("second prepare: %v", err)
	}
	if outcome := <-second.Commit(context.Background(), ticket2); outcome != nativeclipboard.Confirmed {
		t.Fatalf("second commit = %v, want Confirmed", outcome)
	}
	if f.value != "second-secret" || a.clipboardLease != f.owner {
		t.Fatal("a newer connection did not take over the App-owned lease")
	}
	a.Lock()
	if f.value != "" || a.clipboardLease != nil {
		t.Fatal("lock did not clear the shared App-owned lease")
	}
}

// TestBrowserBrokerClipboardDurationIsLiveAndAtomic proves the getter and the
// factory read the atomic mirror, not the UI settings struct, and that zero
// disables automatic clearing without disabling the capability.
func TestBrowserBrokerClipboardDurationIsLiveAndAtomic(t *testing.T) {
	a := New()
	attachFakeClipboard(a)
	if err := a.ConfigureSettingsPath(filepath.Join(t.TempDir(), "settings.json")); err != nil {
		t.Fatal(err)
	}
	cb := a.browserBrokerCallbacks()
	if got := cb.ClipboardClearDuration(); got != 30*time.Second {
		t.Fatalf("initial duration = %v", got)
	}
	for _, seconds := range []int{0, 20, 120, 3600} {
		if err := a.SetClipboardClearSeconds(seconds); err != nil {
			t.Fatalf("set %d: %v", seconds, err)
		}
		want := time.Duration(seconds) * time.Second
		if got := cb.ClipboardClearDuration(); got != want {
			t.Fatalf("duration after %d = %v, want %v", seconds, got, want)
		}
		if _, ttl := cb.NewClipboard(); ttl != want {
			t.Fatalf("factory TTL after %d = %v, want %v", seconds, ttl, want)
		}
	}
	// A settings file load is another mutation entry point and must republish.
	if err := a.SetClipboardClearSeconds(90); err != nil {
		t.Fatal(err)
	}
	if err := a.LoadSettings(); err != nil {
		t.Fatal(err)
	}
	if got := cb.ClipboardClearDuration(); got != 90*time.Second {
		t.Fatalf("duration after reload = %v", got)
	}
	// An out-of-range mirror fails closed instead of silently disabling
	// cleanup; the host refuses such a connection's clipboard state.
	a.clipboardClearSeconds.Store(4000)
	if got := cb.ClipboardClearDuration(); got >= 0 {
		t.Fatalf("invalid mirror = %v, want a negative fail-closed value", got)
	}
}

// TestBrowserBrokerClipboardSettingsRace exercises meaningful settings changes
// alongside several connections building managers and reading the lease
// duration. Only the atomic mirror may be read from those goroutines.
func TestBrowserBrokerClipboardSettingsRace(t *testing.T) {
	if !nativeclipboard.NativeLeaseSupported() {
		t.Skip("native clipboard leases are unavailable; platform fallback has separate coverage")
	}
	a := New()
	f := attachFakeClipboard(a)
	// The real App dispatcher serializes native work on the UI thread; this
	// fake keeps that ordering so the test races only the settings mirror.
	var uiMu sync.Mutex
	a.dispatch = func(fn func()) { uiMu.Lock(); defer uiMu.Unlock(); fn() }
	if err := a.ConfigureSettingsPath(filepath.Join(t.TempDir(), "settings.json")); err != nil {
		t.Fatal(err)
	}
	cb := a.browserBrokerCallbacks()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			valid := func() bool { return true }
			for {
				select {
				case <-stop:
					return
				default:
				}
				m, ttl := cb.NewClipboard()
				if m == nil || ttl < 0 || ttl > time.Hour {
					t.Errorf("factory = %v, %v", m, ttl)
					return
				}
				// The setter may land between the two reads, so both must be a
				// bounded live value rather than one exact snapshot.
				if got := cb.ClipboardClearDuration(); got < 0 || got > time.Hour {
					t.Errorf("getter = %v", got)
					return
				}
				ticket, err := m.Prepare([]byte("race-secret"), time.Now().Add(time.Second), time.Time{}, valid)
				if err != nil {
					t.Errorf("prepare: %v", err)
					return
				}
				// Cancelling the offer never clears a confirmed or foreign
				// native owner, so a competing connection cannot blank a copy.
				m.CancelOffer(ticket)
				m.Close()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			seconds := []int{0, 20, 30, 60, 90, 120, 3600}[i%7]
			if err := a.SetClipboardClearSeconds(seconds); err != nil {
				t.Errorf("set: %v", err)
				break
			}
		}
		close(stop)
	}()
	wg.Wait()
	if f.value != "" && a.clipboardLease == nil {
		t.Fatal("race left an untracked OS clipboard owner")
	}
}
