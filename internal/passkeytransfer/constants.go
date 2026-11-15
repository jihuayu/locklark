package passkeytransfer

import "time"

const (
	version = 1

	maxInvitation    = 16 << 10
	maxPacket        = 2 << 20
	maxPlaintext     = 1 << 20
	maxRecords       = 16
	maxTitle         = 1024
	maxInvitationTTL = 15 * time.Minute

	// Domain separators for fingerprints and signatures. They are not secret;
	// they prevent cross-protocol reuse of the same keys.
	fingerprintDomain = "passme/passkey-transfer/v1/fingerprint\x00"
	invitationDomain  = "passme/passkey-transfer/v1/invitation\x00"
	packetDomain      = "passme/passkey-transfer/v1/packet\x00"
)
