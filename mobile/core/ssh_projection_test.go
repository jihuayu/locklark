package mobilecore

import (
	"github.com/jihuayu/locklark/internal/personal"
	"testing"
)

func TestLegacyMobileLoginProjectionExcludesSSHKeys(t *testing.T) {
	rows := rowsResult([]personal.Row{{Kind: "login", ID: "login"}, {Kind: "ssh-key", ID: "ssh"}, {Kind: "document", ID: "document"}})
	if rows.Count() != 2 {
		t.Fatal("SSH key leaked into legacy mobile login controls")
	}
	for i := 0; i < rows.Count(); i++ {
		r, e := rows.At(i)
		if e != nil || r.ID == "ssh" {
			t.Fatal("SSH projection was not excluded")
		}
	}
}
