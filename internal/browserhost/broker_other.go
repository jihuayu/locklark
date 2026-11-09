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
