// Package remoteunlock defines the standalone v1 canonical codec for the
// remote-unlock TLS exporter binding context.
//
// A ChannelBindingContext is encoded to a single canonical UTF-8 JSON object
// (at most MaxContextSize bytes) that is used as the exporter context of a
// pinned TLS 1.3 channel. EncodeChannelBindingContext writes every member
// manually in the fixed schema order; ParseChannelBindingContext accepts only
// the exact canonical spelling, so every accepted input satisfies
// Encode(Parse(b)) == b.
//
// The wire format is documented in docs/remote-unlock-wire-v1.md.
//
// Scope. This package only encodes and decodes context bytes. It does not
// create or inspect TLS connections, derive exporter output, verify requests,
// device identities, signatures, pairing, membership or policy, authorize
// anything, or handle vault unlock keys (VUK) or their delivery. A successfully
// parsed context is a well-formed claim, not a proven one: a canonical
// encoding alone establishes none of those properties. The package is
// intended for both the macOS process and the remote device, so it is a
// separate public package and depends only on the Go standard library.
package remoteunlock
