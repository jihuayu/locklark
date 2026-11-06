package desktop

import (
	"github.com/jihuayu/locklark/internal/personal"
	"testing"
)

func TestLoginControlsExcludeSSHMetadataProjection(t *testing.T) {
	rows := loginProjection([]personal.Row{{Kind: "ssh-key", ID: "ssh"}, {Kind: "login", ID: "login"}, {Kind: "document", ID: "document"}})
	if len(rows) != 2 || rows[0].ID != "login" || rows[1].ID != "document" {
		t.Fatal("SSH metadata entered legacy native login controls")
	}
}
