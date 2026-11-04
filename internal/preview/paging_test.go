package preview

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestFullInboxCanBePagedPastInvalidMessages(t *testing.T) {
	out := filepath.Join(t.TempDir(), "scenario")
	if err := Create(out, "boot", "synthetic"); err != nil {
		t.Fatal(err)
	}
	inbox := filepath.Join(out, "inbox")
	device := filepath.Join(out, "clients", "B")
	id, err := Submit(inbox, filepath.Join(out, "agent", "approval.pub"), "batch", "synthetic request", FixtureRef)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 128; i++ {
		if err := os.WriteFile(filepath.Join(inbox, fmt.Sprintf("%032x.request.age", i)), []byte("bad"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	page, err := InboxPage(inbox, device, "batch", "")
	if err != nil || len(page.Requests) != 0 || page.Unreadable != 128 || page.Next == "" {
		t.Fatal("first page did not report corruption and progress", page, err)
	}
	page, err = InboxPage(inbox, device, "batch", page.Next)
	if err != nil || len(page.Requests) != 1 || page.Requests[0].ID != id || page.Next != "" {
		t.Fatal("valid receipt lost on subsequent page", page, err)
	}
}
