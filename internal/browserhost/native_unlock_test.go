package browserhost

import (
	"testing"
	"time"
)

// The browser may ask the desktop host to surface its window before pairing;
// the request must be accepted without a capability and answered with the
// same bounded status frame the popup validates.
func TestUnlockRequestWorksBeforePairing(t *testing.T) {
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	if err := c.Handle(Request{V: 1, ID: reqID(41), Type: "unlock-request"}); err != nil {
		t.Fatal(err)
	}
	responses := out.responses(t)
	if len(responses) != 1 {
		t.Fatalf("responses: %d", len(responses))
	}
	got := responses[0]
	if got.Type != "status" || got.ID != reqID(41) {
		t.Fatalf("response: %+v", got)
	}
	if got.DesktopConnected || got.Unlocked || got.Paired {
		t.Fatalf("unpaired host claimed a desktop session: %+v", got)
	}
}
