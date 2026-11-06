//go:build !linux && !darwin && !windows

package sshagent

import "net"

func DefaultEndpoint() (string, error)                 { return "", ErrUnavailable }
func listenLocal(string) (net.Listener, error)         { return nil, ErrUnavailable }
func authenticatedPeer(net.Conn) (Peer, error)         { return Peer{}, ErrRefused }
func prepareConnection(net.Conn) (Peer, []byte, error) { return Peer{}, nil, ErrRefused }
