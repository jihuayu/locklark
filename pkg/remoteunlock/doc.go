// Package remoteunlock defines the standalone v1 canonical codecs for the
// remote-unlock TLS exporter binding context and the stable per-device
// transport binding.
//
// A ChannelBindingContext is encoded to a single canonical UTF-8 JSON object
// (at most MaxContextSize bytes) that is used as the exporter context of a
// pinned TLS 1.3 channel. A DeviceTransportBinding is a separate canonical
// object (at most MaxBindingSize bytes) that identifies one member's device and
// vault across requests; it is stable and deliberately independent of any
// single request. EncodeChannelBindingContext and EncodeDeviceTransportBinding
// write every member manually in the fixed schema order;
// ParseChannelBindingContext and ParseDeviceTransportBinding accept only the
// exact canonical spelling, so every accepted input satisfies
// Encode(Parse(b)) == b.
//
// The wire format is documented in docs/remote-unlock-wire-v1.md.
//
// Scope. This package encodes and decodes context and binding bytes, computes
// the public binding signature preimage in SigningBytes, and verifies a binding
// signature with a caller-pinned Ed25519 public key. It does not create or
// inspect TLS connections, derive exporter output, verify requests, resolve or
// pin device identities or keys, verify enrollment, pairing, membership or
// policy, authorize anything, or handle vault unlock keys (VUK) or their
// delivery. A successfully parsed context or binding is a well-formed claim,
// not a proven one: a canonical encoding alone establishes none of those
// properties. A successful signature check proves only that the supplied
// pinned key signed those exact binding bytes.
//
// The package is intended for both the macOS process and the remote device, so
// it is a separate public package. It depends on the Go standard library and
// filippo.io/age for canonical age X25519 recipient parsing.
package remoteunlock
