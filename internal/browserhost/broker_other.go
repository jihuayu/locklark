//go:build !unix && !windows

package browserhost

import (
	"context"
	"net"
)

func DefaultBrokerEndpoint() (string, error) { return "", ErrBrokerUnavailable }

func listenLocal(string) (net.Listener, error) { return nil, ErrBrokerUnavailable }

func dialLocal(context.Context, string) (net.Conn, error) { return nil, ErrBrokerUnavailable }

func authenticatedPeer(net.Conn) (Peer, error) { return Peer{}, ErrBrokerUnavailable }

// brokerEndpointForClient and dialVerifiedBroker keep unsupported platforms
// fixed-unavailable before any hello or secret request write; they never
// invent an insecure fake peer.
func brokerEndpointForClient() (string, error) { return "", ErrBrokerUnavailable }

func dialVerifiedBroker(context.Context, string) (net.Conn, error) {
	return nil, ErrBrokerUnavailable
}
