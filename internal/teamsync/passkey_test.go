package teamsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/vault"
	"golang.org/x/crypto/ssh"
)

func teamPasskeyRecord(t *testing.T) []byte {
	t.Helper()
	request, err := passkey.Parse("https://example.test", true, []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"team-passkey-canary","displayName":"Team Passkey"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`))
	if err != nil {
		t.Fatal("team passkey request fixture failed")
	}
	raw, _, err := passkey.Create(request, false)
	if err != nil {
		t.Fatal("team passkey record fixture failed")
	}
	t.Cleanup(func() { clear(raw) })
	return raw
}

func TestHTTPSPasskeyAndSSHItemsRoundTrip(t *testing.T) {
	f := newSyncFixture(t, nil)
	record := teamPasskeyRecord(t)
	seed := bytes.Repeat([]byte{0x51}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal("team SSH public fixture failed")
	}
	items := []vault.Item{
		{ID: "passkey-login", Kind: "login", Title: "Team passkey login", Username: "alice", Password: "team-passkey-password", URL: "https://example.test", Passkey: bytes.Clone(record)},
		{ID: "ssh-key", Kind: "ssh-key", Title: "Team SSH key", SSHSeed: bytes.Clone(seed), SSHPublicKey: public.Marshal()},
	}
	proposal, snapshot, err := directory.BuildUpdate(f.cfg, f.keys[0], f.first, items)
	if err != nil {
		t.Fatal("team passkey update build failed", err)
	}
	writer := f.client(t, 0)
	if _, err = writer.Publish(context.Background(), proposal, snapshot); err != nil {
		t.Fatal("team passkey publish failed", err)
	}
	reader := f.client(t, 1)
	state, err := reader.Fetch(context.Background())
	if err != nil || state.Checkpoint().Version != 2 {
		t.Fatal("team passkey read failed", err)
	}
	view := state.View()
	metadata, got, err := vault.OpenItems(view.Snapshot, f.ages[1], view.SnapshotSigner, view.Receipt.Proposal.Epoch)
	if err != nil {
		t.Fatal("team passkey snapshot did not open", err)
	}
	if string(metadata) != "locklark/team/items/v1/"+view.Receipt.Proposal.Scope {
		t.Fatal("team passkey snapshot metadata changed")
	}
	byID := map[string]vault.Item{}
	for _, item := range got {
		byID[item.ID] = item
	}
	login, ok := byID["passkey-login"]
	if !ok || !bytes.Equal(login.Passkey, record) || login.Username != "alice" || login.Password != "team-passkey-password" {
		t.Fatal("team passkey login did not round-trip losslessly")
	}
	if !passkey.ValidRecord(login.Passkey) {
		t.Fatal("team passkey record became invalid after sync")
	}
	key, ok := byID["ssh-key"]
	if !ok || !bytes.Equal(key.SSHSeed, seed) || !bytes.Equal(key.SSHPublicKey, public.Marshal()) {
		t.Fatal("team SSH key did not round-trip losslessly")
	}
	if bytes.Contains(view.Snapshot.Database, record) || bytes.Contains(view.Snapshot.Database, seed) {
		t.Fatal("team snapshot exposed passkey or SSH private material")
	}
	for i := range got {
		clear(got[i].Passkey)
		clear(got[i].SSHSeed)
	}
}
