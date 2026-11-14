//go:build linux

package browserhost

import "testing"

// synthetic only: no proof object can be constructed live outside browserhost.
func TestLinuxCLIRunCTTYNilAndForgedProofRejected(t *testing.T) {
	if !cliRunCTTYProofRequired() {
		t.Fatal("Linux must require the sealed CTTY proof")
	}
	req := cliRunFixtureRequest()
	peer := Peer{User: "UID 501", PID: 4242, Process: "/fixture/bin/locklark"}
	if req.VerifyCLIRunCTTY(peer) {
		t.Fatal("nil proof was accepted")
	}
	req.cttyProof = &clirunCTTYProof{}
	if req.VerifyCLIRunCTTY(peer) {
		t.Fatal("zero proof was accepted")
	}
}
