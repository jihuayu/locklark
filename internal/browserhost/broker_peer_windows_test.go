//go:build windows

package browserhost

import (
	"context"
	"errors"
	"testing"
)

// These run on Windows CI: this host cross-compiles them but cannot execute
// Windows named pipes natively.
func TestBrokerEndpointForClientRefusesUnsafeCustomToken(t *testing.T) {
	t.Setenv("LOCKLARK_BROWSER_SOCKET", "bad/token")

	if _, e := brokerEndpointForClient(); !errors.Is(e, ErrBrokerRefused) {
		t.Fatalf("got %v, want ErrBrokerRefused for an unsafe custom pipe token", e)
	}
}

func TestDialVerifiedBrokerMissingPipeUnavailable(t *testing.T) {
	path, e := brokerEndpointForClient()
	if e != nil {
		t.Fatalf("default endpoint: %v", e)
	}
	if _, e := dialVerifiedBroker(context.Background(), path+"-absent"); !errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("got %v, want ErrBrokerUnavailable for an absent pipe", e)
	}
	if _, e := dialVerifiedBroker(context.Background(), `\\server\pipe\broker`); !errors.Is(e, ErrBrokerRefused) {
		t.Fatalf("got %v, want ErrBrokerRefused for a remote pipe name", e)
	}
}
