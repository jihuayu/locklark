package desktop

import (
	"context"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/browserhost"
)

func TestBrowserPairContextCancellationClearsPendingReview(t *testing.T) {
	a := New()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := a.approveBrowserPair(ctx, browserhost.BrowserPairRequest{
			Peer:    browserhost.Peer{User: "UID 501", PID: 5151, Process: "locklark-browser-firefox"},
			Browser: browserhost.Firefox,
			Origin:  browserhost.FirefoxID,
		})
		result <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.brokerMu.Lock()
		pending := len(a.browserPairs)
		a.brokerMu.Unlock()
		if pending == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pairing review did not surface")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled pairing review returned no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pairing review did not observe context cancellation")
	}
	a.brokerMu.Lock()
	defer a.brokerMu.Unlock()
	if len(a.browserPairs) != 0 {
		t.Fatal("canceled pairing review remained in the native queue")
	}
}
