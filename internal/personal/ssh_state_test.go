package personal

import (
	"errors"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

func TestSSHStateMutationCancelsOutputInsideSessionArbitration(t *testing.T) {
	s, _, row := sshFixture(t)
	i := preparedSSH(t, s, row)
	o, e := s.ApproveSSHSign(i)
	if e != nil {
		t.Fatal("SSH approval")
	}
	g := NewMutationGate(time.Now().Add(time.Minute))
	if s.RegisterMutation(g) != nil {
		t.Fatal("SSH state gate")
	}
	// Exercise the shared locked mutation path directly: its return must already
	// have revoked old outputs, before a public wrapper can run any later work.
	r, e := s.nativeMutation("item.archive", vault.Item{}, &Edit{ID: row.ID, Revision: row.Revision}, commandOption{sshState: true}, g)
	if e != nil || r.revision == "" {
		t.Fatal("SSH archive transaction", e)
	}
	if wire, e := s.ConsumeSSHSignature(o); e == nil || len(wire) != 0 {
		t.Fatal("committed archive left an old signature grantable")
	}
	assertSSHRetired(t, s, i)
}

func TestSSHManagementStateGatesAndRestoration(t *testing.T) {
	s, _, row := sshFixture(t)
	apply := func(revision, action string) (string, error) {
		g := NewMutationGate(time.Now().Add(time.Minute))
		if s.RegisterMutation(g) != nil {
			t.Fatal("state gate")
		}
		return s.SetSSHKeyState(row.ID, revision, action, g)
	}
	archived, e := apply(row.Revision, "item.archive")
	if e != nil {
		t.Fatal("gated archive", e)
	}
	rows, e := s.ListSSHKeysState("archived")
	if e != nil || len(rows) != 1 || rows[0].Revision != archived || rows[0].State != "archived" {
		t.Fatal("SSH archived management metadata")
	}
	if _, e = apply(archived, "item.archive"); !errors.Is(e, ErrAlreadyArchived) {
		t.Fatal("known no-op misreported", e)
	}
	trashed, e := apply(archived, "item.trash")
	if e != nil {
		t.Fatal("SSH trash", e)
	}
	rows, e = s.ListSSHKeysState("trashed")
	if e != nil || len(rows) != 1 || rows[0].Revision != trashed {
		t.Fatal("SSH trash management metadata")
	}
	restored, e := apply(trashed, "item.untrash")
	if e != nil {
		t.Fatal("SSH restore", e)
	}
	rows, e = s.ListSSHKeysState("all")
	if e != nil || len(rows) != 1 || rows[0].State != "archived" || rows[0].Revision != restored {
		t.Fatal("SSH restore lost prior archive state")
	}
	active, e := apply(restored, "item.unarchive")
	if e != nil {
		t.Fatal("SSH reactivate")
	}
	rows, e = s.ListSSHKeys()
	if e != nil || len(rows) != 1 || rows[0].State != "active" || rows[0].Revision != active {
		t.Fatal("SSH agent identities not restored")
	}
	if _, e = s.ListSSHKeysState("unknown"); !errors.Is(e, ErrSSHKey) {
		t.Fatal("unknown management state accepted")
	}
	all, e := s.List("all")
	if e != nil {
		t.Fatal("general metadata")
	}
	for _, r := range all {
		if r.ID == row.ID && r.Kind != "ssh-key" {
			t.Fatal("general metadata omitted explicit kind")
		}
	}
}
