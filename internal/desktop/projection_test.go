package desktop

import (
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
)

func TestLoginControlsExcludeNonLoginMetadataProjection(t *testing.T) {
	rows := loginProjection([]personal.Row{
		{Kind: "ssh-key", ID: "ssh"}, {Kind: "login", ID: "login"}, {Kind: "document", ID: "document"},
		{Kind: "credit_card", ID: "card"}, {Kind: "identity", ID: "identity"}, {Kind: "secure_note", ID: "note"},
	})
	// Only logins may reach the classic native read/mutation controls; every
	// other kind would be refused as "invalid" and lock the session.
	if len(rows) != 1 || rows[0].ID != "login" || rows[0].Kind != "login" {
		t.Fatal("non-login items entered legacy native login controls")
	}
}
