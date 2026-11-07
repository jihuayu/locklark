package desktop

import (
	"context"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/browserhost"
)

func TestCLIRunApprovalCannotPublishAfterLock(t *testing.T) {
	a := dailyAppFixture(t)
	a.notifyBrowserBrokerUnlocked()
	s, epoch := a.brokerSession, a.brokerEpoch
	a.Lock()
	approved, err := a.requestCLIRunApproval(context.Background(), browserhost.Peer{}, browserhost.BrokerCLIRequest{}, s, epoch)
	if approved || err == nil || a.cliPending != nil {
		t.Fatal("an old session published an approval after lock")
	}
}

func TestCLIRunLockCancelsPendingApproval(t *testing.T) {
	a := dailyAppFixture(t)
	a.notifyBrowserBrokerUnlocked()
	s, epoch := a.brokerSession, a.brokerEpoch
	result := make(chan bool, 1)
	go func() {
		approved, _ := a.requestCLIRunApproval(context.Background(), browserhost.Peer{}, browserhost.BrokerCLIRequest{}, s, epoch)
		result <- approved
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.brokerMu.Lock()
		pending := a.cliPending != nil
		a.brokerMu.Unlock()
		if pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("approval was not published")
		}
		time.Sleep(time.Millisecond)
	}
	a.Lock()
	select {
	case approved := <-result:
		if approved {
			t.Fatal("lock approved a pending disclosure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lock did not cancel the pending approval")
	}
}
