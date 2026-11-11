//go:build linux || darwin

package browserhost

// peerBeforeHello is false on Unix: the broker reads the hello only after
// authenticatedPeer has checked the connected socket's peer credentials.
const peerBeforeHello = false
